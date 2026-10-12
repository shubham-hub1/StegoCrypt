import streamlit as st
import cv2
import numpy as np
import zstandard as zstd
import random
import math
from io import BytesIO
from PIL import Image
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from skimage.metrics import structural_similarity as ssim
from reedsolo import RSCodec, ReedSolomonError

# ==========================================
# 1. CONFIGURATION
# ==========================================
# 4x Capacity Mid-Frequency Zig-Zag Pattern
DCT_COORDS = [(3, 3), (3, 4), (4, 3), (4, 4)]
BITS_PER_BLOCK = len(DCT_COORDS)

HEADER_STEP = 64
# 128 bits (Salt) + 8 bits (Step Size) + 32 bits (RS Payload Length) = 168 bits
HEADER_BITS = 168
HEADER_BLOCKS = math.ceil(HEADER_BITS / BITS_PER_BLOCK)

RS_ECC_SYMBOLS = 32
rs = RSCodec(RS_ECC_SYMBOLS)


def embed_bit_qim(coeff, bit, step):
    q = int(round(coeff / step))
    if (q % 2) != bit:
        if coeff > (q * step):
            q += 1
        else:
            q -= 1
    return float(q * step)


def extract_bit_qim(coeff, step):
    q = int(round(coeff / step))
    return q % 2


def get_max_capacity(image_bytes):
    # Use PIL to read dimensions without decoding full image array
    img = Image.open(BytesIO(image_bytes))
    w, h = img.size

    total_blocks = (h // 8) * (w // 8)
    if total_blocks <= HEADER_BLOCKS:
        return 0

    available_payload_bits = (total_blocks - HEADER_BLOCKS) * BITS_PER_BLOCK
    available_rs_bytes = available_payload_bits // 8

    # Calculate Reed-Solomon chunks (255 max bytes per chunk: 223 data + 32 parity)
    full_chunks = available_rs_bytes // 255
    remainder = available_rs_bytes % 255

    if remainder <= RS_ECC_SYMBOLS:
        remainder_data = 0
    else:
        remainder_data = remainder - RS_ECC_SYMBOLS

    max_raw_transmission = (full_chunks * (255 - RS_ECC_SYMBOLS)) + remainder_data

    # Subtract ChaCha20 Crypto Overhead: Length(4) + Nonce(12) + Tag(16) = 32 bytes
    crypto_overhead = 32
    max_compressed_size = max_raw_transmission - crypto_overhead

    return max(0, max_compressed_size)


# ==========================================
# 2. CORE PIPELINE FUNCTIONS
# ==========================================
def embed_data(image_bytes, message, password, step_size):
    # 1. Prepare Key and Encrypt
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32, count=100000, hmac_hash_module=SHA256)

    compressor = zstd.ZstdCompressor(level=22)
    compressed_payload = compressor.compress(message.encode('utf-8'))

    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(compressed_payload)
    nonce = cipher.nonce

    data_body = nonce + tag + ciphertext
    data_len = len(data_body).to_bytes(4, byteorder='big')
    raw_transmission = bytearray(data_len + data_body)

    # 2. Apply Reed-Solomon Error Correction
    rs_encoded_payload = list(rs.encode(raw_transmission))
    rs_byte_length = len(rs_encoded_payload)

    # 3. Build Header and Bitstream
    salt_bits = [int(b) for byte in salt for b in f"{byte:08b}"]
    step_bits = [int(b) for b in f"{step_size:08b}"]
    length_bits = [int(b) for b in f"{rs_byte_length:032b}"]
    header_bits = salt_bits + step_bits + length_bits

    payload_bits = [int(b) for byte in rs_encoded_payload for b in f"{byte:08b}"]
    bitstream = header_bits + payload_bits
    total_bits = len(bitstream)

    # 4. Read Image
    img_array = np.asarray(bytearray(image_bytes), dtype=np.uint8)
    cover_image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    if cover_image is None:
        raise ValueError("Could not decode the cover image.")

    b_channel, g_channel, r_channel = cv2.split(cover_image)
    embed_channel = np.float32(b_channel)
    h, w = embed_channel.shape

    # 5. Generate PRNG Embedding Path
    all_blocks = [(i, j) for i in range(0, h - 7, 8) for j in range(0, w - 7, 8)]
    required_blocks = math.ceil(total_bits / BITS_PER_BLOCK)

    if len(all_blocks) < required_blocks:
        raise ValueError(
            f"Image too small. Need {required_blocks} blocks, but image only has {len(all_blocks)}."
        )

    header_path = all_blocks[:HEADER_BLOCKS]
    payload_pool = all_blocks[HEADER_BLOCKS:]

    prng = random.Random(int.from_bytes(key, 'big'))
    prng.shuffle(payload_pool)

    payload_blocks_needed = math.ceil(len(payload_bits) / BITS_PER_BLOCK)
    embedding_path = header_path + payload_pool[:payload_blocks_needed]

    # 6. Embed Data (Multi-Coefficient)
    bit_idx = 0
    for (i, j) in embedding_path:
        if bit_idx >= total_bits:
            break

        block = embed_channel[i:i + 8, j:j + 8]
        dct_block = cv2.dct(block)

        for coord in DCT_COORDS:
            if bit_idx >= total_bits:
                break

            current_step = HEADER_STEP if bit_idx < HEADER_BITS else step_size
            dct_block[coord] = embed_bit_qim(dct_block[coord], bitstream[bit_idx], step=current_step)
            bit_idx += 1

        embed_channel[i:i + 8, j:j + 8] = cv2.idct(dct_block)

    # 7. Reconstruct & Metrics
    mod_channel = np.uint8(np.clip(embed_channel, 0, 255))
    stego_bgr = cv2.merge([mod_channel, g_channel, r_channel])

    psnr_value = cv2.PSNR(cover_image, stego_bgr)
    ssim_value = ssim(cover_image, stego_bgr, channel_axis=2, data_range=255)

    is_success, buffer = cv2.imencode(".png", stego_bgr)
    if not is_success:
        raise RuntimeError("Failed to encode stego-image to PNG.")

    return buffer.tobytes(), len(payload_bits), total_bits, psnr_value, ssim_value


def extract_data(image_bytes, password):
    # 1. Read Stego Image
    img_array = np.asarray(bytearray(image_bytes), dtype=np.uint8)
    stego_image = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    if stego_image is None:
        raise ValueError("Could not decode stego image.")

    rec_b, _, _ = cv2.split(stego_image)
    rec_float = np.float32(rec_b)
    h, w = rec_float.shape

    all_blocks = [(i, j) for i in range(0, h - 7, 8) for j in range(0, w - 7, 8)]
    if len(all_blocks) < HEADER_BLOCKS:
        raise ValueError("Image is too small to contain a valid header.")

    # 2. Extract 168-bit Header
    header_bits = []
    for (i, j) in all_blocks[:HEADER_BLOCKS]:
        if len(header_bits) >= HEADER_BITS:
            break
        block = rec_float[i:i + 8, j:j + 8]
        dct_block = cv2.dct(block)

        for coord in DCT_COORDS:
            if len(header_bits) >= HEADER_BITS:
                break
            header_bits.append(extract_bit_qim(dct_block[coord], step=HEADER_STEP))

    header_binary = "".join(str(bit) for bit in header_bits)

    salt_bytes = int(header_binary[:128], 2).to_bytes(16, byteorder='big')
    dynamic_step_size = int(header_binary[128:136], 2)
    rs_byte_length = int(header_binary[136:168], 2)
    target_payload_bits = rs_byte_length * 8

    if dynamic_step_size < 8 or dynamic_step_size > 255:
        raise ValueError("Invalid header detected. Image is corrupted or was altered.")

    # 3. Derive Key and Recreate PRNG Path
    key = PBKDF2(password, salt_bytes, 32, count=100000, hmac_hash_module=SHA256)

    payload_pool = all_blocks[HEADER_BLOCKS:]
    prng = random.Random(int.from_bytes(key, 'big'))
    prng.shuffle(payload_pool)

    payload_blocks_needed = math.ceil(target_payload_bits / BITS_PER_BLOCK)
    if payload_blocks_needed > len(payload_pool):
        raise ValueError("Image is missing data. It may have been cropped.")

    extraction_path = payload_pool[:payload_blocks_needed]

    # 4. Extract Payload Bits
    payload_bits = []
    for (i, j) in extraction_path:
        if len(payload_bits) >= target_payload_bits:
            break
        block = rec_float[i:i + 8, j:j + 8]
        dct_block = cv2.dct(block)

        for coord in DCT_COORDS:
            if len(payload_bits) >= target_payload_bits:
                break
            payload_bits.append(extract_bit_qim(dct_block[coord], step=dynamic_step_size))

    # 5. Decode RS-ECC & ChaCha20
    rs_bytes = bytearray()
    for b in range(0, len(payload_bits), 8):
        byte_val = int("".join(str(bit) for bit in payload_bits[b:b + 8]), 2)
        rs_bytes.append(byte_val)

    try:
        corrected_bytes = rs.decode(rs_bytes)[0]
    except ReedSolomonError:
        raise ValueError("Too many bit errors occurred. Reed-Solomon correction failed to recover the data.")

    total_expected_len = int.from_bytes(corrected_bytes[:4], byteorder='big')
    payload = corrected_bytes[4: 4 + total_expected_len]

    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]

    decipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        decrypted_compressed = decipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        raise ValueError("MAC check failed. Incorrect password or image corrupted beyond repair.")

    decompressor = zstd.ZstdDecompressor()
    return decompressor.decompress(decrypted_compressed).decode('utf-8')


# ==========================================
# 3. STREAMLIT UI
# ==========================================
st.set_page_config(page_title="StegoVault DCT", layout="centered")
st.title("🔒 StegoVault: Ultimate Architecture")
st.markdown("ChaCha20 + RS-ECC + PRNG Scrambling + High-Capacity Multi-Coefficient.")

tab_embed, tab_extract = st.tabs(["📤 Embed Data", "📥 Extract Data"])

with tab_embed:
    cover_file = st.file_uploader("Upload Cover Image (PNG, JPG)", type=["png", "jpg", "jpeg"])
    if cover_file:
        st.image(cover_file, caption="Cover Image Preview", use_container_width=True)

        max_bytes = get_max_capacity(cover_file.getvalue())

        secret_message = st.text_area("Secret Message", height=150)
        current_bytes = len(secret_message.encode('utf-8'))

        if max_bytes > 0:
            fill_pct = min(current_bytes / max_bytes, 1.0)
            st.progress(fill_pct, text=f"Guaranteed Capacity: {current_bytes} / {max_bytes} bytes")

            if current_bytes > max_bytes:
                st.warning(
                    "⚠️ You exceeded the guaranteed limit. Zstandard compression might still make it fit, but embedding may fail."
                )
        else:
            st.error("Image is too small to hold any data!")

    embed_password = st.text_input("Encryption Password", type="password", key="embed_pass")

    embed_step = st.slider(
        "Robustness vs Quality (Step Size)",
        min_value=8, max_value=128, value=16, step=8,
        help="Higher = Survives heavier degradation. Lower = Higher visual fidelity."
    )

    if st.button("Encrypt, Scramble & Embed", type="primary"):
        if not cover_file or not secret_message or not embed_password:
            st.error("Please provide an image, a message, and a password.")
        else:
            with st.spinner("Scrambling blocks and embedding at 4x capacity..."):
                try:
                    stego_bytes, embedded, total, psnr, ssim_val = embed_data(
                        cover_file.getvalue(), secret_message, embed_password, embed_step
                    )

                    st.success(f"Embedded {embedded} encrypted payload bits successfully!")

                    col1, col2 = st.columns(2)
                    col1.metric(label="Image Quality (PSNR)", value=f"{psnr:.2f} dB")
                    col2.metric(label="Structural Similarity (SSIM)", value=f"{ssim_val:.4f}")

                    st.download_button(
                        label="Download Stego-Image (PNG)",
                        data=stego_bytes,
                        file_name="stego_image.png",
                        mime="image/png"
                    )
                except Exception as e:
                    st.error(f"Error during embedding: {str(e)}")

with tab_extract:
    stego_file = st.file_uploader("Upload Stego-Image (PNG ONLY)", type=["png"])
    if stego_file:
        st.image(stego_file, caption="Stego-Image Preview", use_container_width=True)

    extract_password = st.text_input("Decryption Password", type="password", key="extract_pass")

    if st.button("Extract, Repair & Decrypt"):
        if not stego_file or not extract_password:
            st.error("Please upload the stego-image and enter the password.")
        else:
            with st.spinner("Mapping PRNG path and repairing bits..."):
                try:
                    recovered_msg = extract_data(stego_file.getvalue(), extract_password)
                    st.success("Message successfully reconstructed from random blocks!")
                    st.text_area("Recovered Message", recovered_msg, height=200)
                except ValueError as ve:
                    st.error(f"Decryption failed: {str(ve)}")
                except Exception as e:
                    st.error(f"Error: {str(e)}")