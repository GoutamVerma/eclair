package fr.acinq.eclair.api

import fr.acinq.bitcoin.psbt.Psbt
import fr.acinq.bitcoin.scalacompat.{DeterministicWallet, MnemonicCode}
import fr.acinq.eclair.api.handlers.HardwareWalletInterface._
import org.scalatest.funsuite.AnyFunSuite

import java.util.Base64

class HardwareWalletInterfaceSpec extends AnyFunSuite {
  test("compute descriptor checksums") {
    val data = Seq(
        "pkh([6ded4eb8/44h/0h/0h]xpub6C6N5WVF5zmurBR52MZZj8Jxm6eDiKyM4wFCm7xTYBEsAvJPqBKp2u2K7RTsZaYDN8duBWq4acrD4vrwjaKHTYuntGjL334nVHtLNuaj5Mu/0/*)#5mzpq0w6",
        "wpkh([6ded4eb8/84h/0h/0h]xpub6CDeom4xT3Wg7BuyXU2Sd9XerTKttyfxRwJE36mi5HxFYpYdtdwM76Zx8swPnc6zxuArMYJgjNy91fJ13YtGPHgf49YqA8KdXg6D69tzNFh/0/*)#refya6f0",
        "sh(wpkh([6ded4eb8/49h/0h/0h]xpub6Cb8jR9kYsfC6kj9CsE18SyudWjW2V3FnBFkT2oqq6n7NWWvJrjhFin3sAYg8X7ApX8iPophBa98mo4nMvSxnqrXvpnwaRopecQz859Ai1s/0/*))#xrhyhtvl",
        "tr([6ded4eb8/86h/0h/0h]xpub6CDp1iw76taes3pkqfiJ6PYhwURkaYksJ62CrrdTVr6ow9wR9mKAtUGoZQqb8pRDiq2F8k31tYrrJjVGTRSLYGQ7nYpmewH94ThsAgDxJ4h/0/*)#2nm7drky",
        "pkh([6ded4eb8/44h/0h/0h]xpub6C6N5WVF5zmurBR52MZZj8Jxm6eDiKyM4wFCm7xTYBEsAvJPqBKp2u2K7RTsZaYDN8duBWq4acrD4vrwjaKHTYuntGjL334nVHtLNuaj5Mu/1/*)#908qa67z",
        "wpkh([6ded4eb8/84h/0h/0h]xpub6CDeom4xT3Wg7BuyXU2Sd9XerTKttyfxRwJE36mi5HxFYpYdtdwM76Zx8swPnc6zxuArMYJgjNy91fJ13YtGPHgf49YqA8KdXg6D69tzNFh/1/*)#jdv9q0eh",
        "sh(wpkh([6ded4eb8/49h/0h/0h]xpub6Cb8jR9kYsfC6kj9CsE18SyudWjW2V3FnBFkT2oqq6n7NWWvJrjhFin3sAYg8X7ApX8iPophBa98mo4nMvSxnqrXvpnwaRopecQz859Ai1s/1/*))#nzej05eq",
        "tr([6ded4eb8/86h/0h/0h]xpub6CDp1iw76taes3pkqfiJ6PYhwURkaYksJ62CrrdTVr6ow9wR9mKAtUGoZQqb8pRDiq2F8k31tYrrJjVGTRSLYGQ7nYpmewH94ThsAgDxJ4h/1/*)#m87lskxu"
    )
    data.foreach(dnc => {
      val Array(desc, checksum) = dnc.split('#')
      assert(checksum == descriptorChecksum(desc))
    })
  }

  test("sign psbt") {
    val mnemonics = "book mandate inside morning lucky result cruel other frame dragon property chimney"
    val seed = MnemonicCode.toSeed(mnemonics, "")
    val master = DeterministicWallet.generate(seed)
    val psbt = Psbt.read(Base64.getDecoder.decode("cHNidP8BAHECAAAAAZXIAzLiuUcKD2e0lsHXND/fPxhfO7gFhyB4MoMHX6w2AAAAAAD9////AnMQECQBAAAAFgAU2blGufhu9/wPe15+Ah/WHOhHU2gA4fUFAAAAABYAFKFyP4kfYXpfPXI6yFI4x80G1tLvlgAAAAABAIQCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBGgD/////AgDyBSoBAAAAFgAUoXI/iR9hel89cjrIUjjHzQbW0u8AAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABAR8A8gUqAQAAABYAFKFyP4kfYXpfPXI6yFI4x80G1tLvIgYDfXHH607VnYJXsE/vjqrYN8gQQDiIB6dOCLoD1pZN460cbJoIalQAAIABAACAAAAAgAAAAAAAAAAAAAAAAAAiAgNCNm1/smWTCPh7KO4QRZqNBx17BDVzCPhehUuQuuh1ixxsmghqVAAAgAEAAIAAAACAAQAAAAEAAAAAAAAAACICA31xx+tO1Z2CV7BP746q2DfIEEA4iAenTgi6A9aWTeOtHGyaCGpUAACAAQAAgAAAAIAAAAAAAAAAAAAAAAAA")).getRight
    val psbt1 = signPsbt(master, psbt)
    val tx = psbt1.extract()
    assert(tx.isRight)
  }
}
