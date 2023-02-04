# SPDX-License-Identifier: MIT
using NistCavp
using Test

@testset "NistCavp.jl" begin
    @test 0 == fakeHashFunction()
end

include("SHA.jl")
