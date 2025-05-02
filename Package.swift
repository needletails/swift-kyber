// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-kyber",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftKyber",
            targets: ["SwiftKyber"]),
    ],
    targets: [
        .target(
            name: "CKyberBoringSSL",
            exclude: [
                "hash.txt",
                "include/boringssl_prefix_symbols_nasm.inc",
                "CMakeLists.txt",
                /*
                 * These files are excluded to support WASI libc which doesn't provide <netdb.h>.
                 * This is safe for all platforms as we do not rely on networking features.
                 */
                "crypto/bio/connect.cc",
                "crypto/bio/socket_helper.cc",
                "crypto/bio/socket.cc",
            ],
            cSettings: [
                // These defines come from BoringSSL's build system
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [Platform.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [Platform.windows])),
                .define("NOMINMAX", .when(platforms: [Platform.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [Platform.windows])),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
                .define(
                    "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
                    .when(platforms: [Platform.wasi])
                ),
                .define("OPENSSL_NO_ASM", .when(platforms: [Platform.wasi])),
            ]
        ),
        .target(
            name: "CLibOQS",
            dependencies: ["CKyberBoringSSL"],
            cSettings: [
                .headerSearchPath("Sources/CKyberBoringSSL/include"),
                .headerSearchPath("include"),
                .headerSearchPath("src/oldpqclean_kyber1024_aarch64"),
                .headerSearchPath("src/pqclean_shims"),
                .headerSearchPath("src/pqcrystals-kyber_kyber1024_avx2"),
                .headerSearchPath("src/pqcrystals-kyber_kyber1024_ref"),
                .headerSearchPath("src/sha3"),
                .headerSearchPath("src/sha3/xkcp_low/KeccakP-1600/avx2"),
                .headerSearchPath("src/sha3/xkcp_low/KeccakP-1600/plain-64bits"),
                .headerSearchPath("src/sha3/xkcp_low/KeccakP-1600times4/avx2"),
                .headerSearchPath("src/sha3/xkcp_low/KeccakP-1600times4/serial"),
                .define("OQS_DIST_BUILD"),
                .define("OQS_ENABLE_KEM_kyber_1024_aarch64", .when(platforms: [.iOS, .macOS])),
                .define("OQS_ENABLE_KEM_kyber_1024"),
            ]
        ),
        .target(
            name: "SwiftKyber",
            dependencies: ["CLibOQS"]
        ),
        .testTarget(
            name: "SwiftKyberTests",
            dependencies: [
                "SwiftKyber"
            ]
        ),
    ]
)
