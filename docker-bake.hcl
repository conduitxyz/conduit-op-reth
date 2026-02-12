variable "DEV_PLATFORM" {
    default = BAKE_LOCAL_PLATFORM == "darwin/arm64/v8" ? "linux/arm64" : BAKE_LOCAL_PLATFORM
}

target "_prod" {
    output = ["type=image"]
    platforms = [
        "linux/amd64",
    ]
    inherits = ["generated-tags"]
}

target "generated-tags" {}

target "_dev" {
    output = ["type=docker"]
    platforms = [DEV_PLATFORM]
}

target "conduit-op-reth" {
    inherits = ["_dev"]
    dockerfile = "Dockerfile"
    target = "conduit-op-reth-k8s"
    tags = ["conduit-op-reth"]
}

target "conduit-op-reth-prod" {
    inherits = ["conduit-op-reth", "_prod"]
    args = {
        TARGETPLATFORM = "linux/amd64"
    }
}
