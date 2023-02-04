# SPDX-License-Identifier: MIT
using SHA

@testset "SHA.jl" begin
    ref_sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    @test ref_sha == bytes2hex(sha256("test"))
end
