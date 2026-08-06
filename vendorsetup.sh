# Patch source
./device/samsung/sm8550-common/apply-patches.sh

# Replace ImsMedia
rm -rf packages/modules/ImsMedia
git clone https://github.com/samsung-sm8550-cola2261/ImsMedia packages/modules/ImsMedia
