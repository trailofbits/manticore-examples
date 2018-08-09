pip uninstall -y Manticore || echo "Manticore not cached"
git clone https://github.com/trailofbits/manticore.git
git --no-pager log -1
cd manticore
pip install .
cd ..
