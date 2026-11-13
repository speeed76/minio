#!/bin/zsh
# Build the speeed76/minio security-fork binaries for linux/amd64 with a real version stamp, plus sha256 files.
#   zsh scripts/security/build-release.zsh <out-dir> <YYYY-MM-DDTHH:MM:SSZ>
# The stamp follows upstream's ldflags (buildscripts/gen-ldflags.go): Version (RFC 3339), ReleaseTag (RELEASE.<time>),
# CommitID / ShortCommitID of this tree. Release 1 (2026-11-13) shipped without it and printed DEVELOPMENT.GOGET.
set -eu
out=${1:?out dir}; when=${2:?time like 2026-11-13T10:00:00Z}
tag="RELEASE.${when//:/-}"
commit=$(git rev-parse HEAD)
year=${when[1,4]}
mkdir -p $out
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags kqueue -ldflags "-s -w \
  -X github.com/minio/minio/cmd.Version=$when -X github.com/minio/minio/cmd.CopyrightYear=$year \
  -X github.com/minio/minio/cmd.ReleaseTag=$tag -X github.com/minio/minio/cmd.CommitID=$commit \
  -X github.com/minio/minio/cmd.ShortCommitID=${commit[1,12]}" -o $out/minio-linux-amd64 .
(cd $out && shasum -a 256 minio-linux-amd64 > minio-linux-amd64.sha256sum && cat minio-linux-amd64.sha256sum)
print "tag $tag commit ${commit[1,12]}"
