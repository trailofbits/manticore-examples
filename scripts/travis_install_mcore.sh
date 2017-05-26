pip uninstall -y Manticore || echo "Manticore not cached"
git clone https://github.com/trailofbits/manticore.git
cd manticore
pip install .
cd ..
