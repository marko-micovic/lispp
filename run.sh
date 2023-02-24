nfp4build \
    --output-nffw-filename ./build/firmware.nffw \
    --sandbox-c lispp.c \
    --define FORCE_INLINE \
    --incl-p4-build lispp.p4 \
    --sku AMDA0096-0001:0 \
    --platform lithium \
    --reduced-thread-usage \
    --no-debug-info \
    --nfcc-ng \
    --nfp4c_graphs \
    --nfp4c_p4_version 16 \
    --nfp4c_p4_compiler p4c-nfp \
    --nfirc_default_table_size 65536 \
    --nfirc_implicit_header_valid

rtecli design-load \
    -f build/firmware.nffw \
    -p build/pif_design.json \
    -c lispp.p4cfg
