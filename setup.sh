#!/data/data/com.termux/files/usr/bin/bash
# DANIYAL KHAN PRO - Termux Setup

echo "[*] Updating packages..."
pkg update -y && pkg upgrade -y

echo "[*] Installing system deps..."
pkg install -y python android-tools termux-api libjpeg-turbo libpng

echo "[*] Installing Python packages..."
pip install --upgrade pip
pip install Flask "qrcode[pil]" zeroconf

echo "[*] Creating output dirs..."
mkdir -p ~/daniyal-pro/output/{reports,screenshots,payloads,logs}

echo "[*] Acquiring wake-lock..."
termux-wake-lock 2>/dev/null || true

echo ""
echo "==========================================="
echo "  Setup complete!"
echo "==========================================="
echo ""
echo "To run:"
echo "  cd ~/daniyal-pro"
echo "  python app.py"
echo ""
echo "Then open in your Android browser:"
echo "  http://127.0.0.1:5000"
echo ""
