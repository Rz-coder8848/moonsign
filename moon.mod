// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "Rz-coder8848/moonsign"

version = "0.5.0"

readme = "README.md"

repository = "https://github.com/Rz-coder8848/moonsign"

license = "Apache-2.0"

keywords = [ "pdf", "signature", "pades", "cms", "digital-signature" ]

preferred_target = "native"

description = "Pure-MoonBit PAdES/CMS PDF signing and verification"

import {
  "moonbitlang/pdflite@0.4.1",
  "cc06b/mooncry@0.95.0",
  "moonbitlang/x@0.5.6",
  "moonbitlang/async@0.22.5",
}
