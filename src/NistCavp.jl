# SPDX-License-Identifier: MIT
module NistCavp

export fakeHashFunction
include("hash_functions.jl")

function fakeHashFunction()
    return 0x00
end

end # NistCavp