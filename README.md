A utility to pull down an image, extract named kernel modules from it, sign them with the provided keys, and add htem back in as a new layer, then upload that new image under a new tag.

It operates as a wrapper around the sign-file` binary provided as part of the kernel-devel package  ( aa wrapper rather than a reimplementation to ensure its bug-for-bug compatabile, rather then having awhole new set of bugs of its own). sign-file is distributed as part of the kernel source so in theory is kernel version specific but in reality it hasn't changed to 5+ years, and for kernel modules to be whitelisted across major RHEL versions the signing format also has to be compatable so this is not a major concer.

Currently all config is down via the following environment variables:

- UNSIGNEDIMAGE  the image to pull down
- SIGNEDIMAGE  the tag for the new (signed) image
- FILESTOSIGN  a colon seperated list of the full paths to files to sign
- KEYSECRET  the path to the private key
- CERTSECRET  the path to the public key 


