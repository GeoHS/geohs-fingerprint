{ mkDerivation, base, bytestring, cryptonite, deepseq, memory
, stdenv, template-haskell
}:
mkDerivation {
  pname = "geohs-fingerprint";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring cryptonite deepseq memory template-haskell
  ];
  homepage = "https://github.com/GeoHS/geohs-fingerprint";
  description = "Typeclass for things that an efficient fingerprint can be calculated";
  license = stdenv.lib.licenses.bsd3;
}
