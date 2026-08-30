VERSION ?= 0.3.0

.PHONY: all image sign verify clean

all: image sign

image:
	@echo "Building GARUDA USB Agent Alpine Linux image (v$(VERSION))..."
	bash usb-build/build_image.sh $(VERSION)
	# Output: garuda-usb-$(VERSION).img

sign:
	@echo "Signing USB image with GPG Ed25519 key..."
	bash usb-build/sign.sh garuda-usb-$(VERSION).img
	# Output: garuda-usb-$(VERSION).img.asc

verify:
	@echo "Verifying image signature..."
	gpg --verify garuda-usb-$(VERSION).img.asc garuda-usb-$(VERSION).img

clean:
	rm -f garuda-usb-*.img garuda-usb-*.img.asc garuda-readonly.squashfs
