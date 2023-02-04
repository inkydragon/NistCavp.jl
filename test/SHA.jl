# SPDX-License-Identifier: MIT
using NistCavp
using SHA


@testset "SHA.jl" begin
    ref_sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    @test ref_sha == bytes2hex(sha256("test"))

    @testset "NIST CAVS Test for SHA1/2" begin
        for (sha_func, p) in CAVS_TESTSET_12
            hash = sha12_csvs_msg(sha_func)
            @testset "$(p.name)" begin
                for (idx, val) in p.cavs_vec
                    @test hash[idx+1] == val
                end
            end
        end
    end

    @testset "NIST CAVS Test for SHA3" begin
        for (sha_func, p) in CAVS_TESTSET_3
            hash = sha3_csvs_msg(sha_func)
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
                    @test sha_func(key_gen(key_len), msg) |> bytes2hex == lowercase.(mac)
                end
            end
        end
    end
end # "SHA.jl"
