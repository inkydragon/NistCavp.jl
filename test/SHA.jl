# SPDX-License-Identifier: MIT
using NistCavp
using SHA

SHA12_FUNC = Dict(
    :sha1 => sha1,
    # :sha224 => sha224,
    # :sha256 => sha256,
    # :sha384 => sha384,
    # :sha512 => sha512,

    :sha2_224 => sha2_224,
    :sha2_256 => sha2_256,
    :sha2_384 => sha2_384,
    :sha2_512 => sha2_512
) # SHA12_FUNC

SHA3_FUNC = Dict(
    :sha3_224 => sha3_224,
    :sha3_256 => sha3_256,
    :sha3_384 => sha3_384,
    :sha3_512 => sha3_512
) # SHA3_FUNC

HMAC_FUNC = Dict(
    :hmac_sha1 => hmac_sha1,
    # :hmac_sha224 => hmac_sha224,
    # :hmac_sha256 => hmac_sha256,
    # :hmac_sha384 => hmac_sha384,
    # :hmac_sha512 => hmac_sha512,

    :hmac_sha2_224 => hmac_sha2_224,
    :hmac_sha2_256 => hmac_sha2_256,
    :hmac_sha2_384 => hmac_sha2_384,
    :hmac_sha2_512 => hmac_sha2_512, :hmac_sha3_224 => hmac_sha3_224,
    :hmac_sha3_256 => hmac_sha3_256,
    :hmac_sha3_384 => hmac_sha3_384,
    :hmac_sha3_512 => hmac_sha3_512
) # HMAC_FUNC

@testset "SHA.jl" begin
    ref_sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    @test ref_sha == bytes2hex(sha256("test"))

    @testset "NIST CAVS Test for SHA1/2" begin
        for (sha_func, p) in CAVS_TESTSET_12
            hash = sha12_csvs_msg(SHA12_FUNC[sha_func])
            @testset "$(p.name)" begin
                for (idx, val) in p.cavs_vec
                    @test hash[idx+1] == val
                end
            end
        end
    end

    @testset "NIST CAVS Test for SHA3" begin
        for (sha_func, p) in CAVS_TESTSET_3
            hash = sha3_csvs_msg(SHA3_FUNC[sha_func])
            @testset "$(p.name)" begin
                for (idx, val) in p.cavs_vec
                    @test hash[idx+1] == val
                end
            end
        end
    end

    @testset "NIST example values test" begin
        for (sha_func, test) in NIST_EXAMPLE_VAL
            @testset "$(sha_func)" begin
                for (key_len, msg, mac) in test
                    @test HMAC_FUNC[sha_func](key_gen(key_len), msg) |> bytes2hex == lowercase.(mac)
                end
            end
        end
    end
end # "SHA.jl"
