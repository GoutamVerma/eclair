package fr.acinq.eclair.api.handlers

import akka.http.scaladsl.server.Route
import fr.acinq.bitcoin.ScriptWitness
import fr.acinq.bitcoin.psbt.Psbt
import fr.acinq.bitcoin.scalacompat.DeterministicWallet.{ExtendedPrivateKey, KeyPath, derivePrivateKey, encode, fingerprint, hardened, publicKey, tpub, vpub, xpub}
import fr.acinq.bitcoin.scalacompat.{Block, DeterministicWallet, MnemonicCode}
import fr.acinq.eclair.api.Service
import fr.acinq.eclair.api.directives.EclairDirectives
import org.json4s.{JArray, JBool, JObject, JString}

import java.util.Base64
import scala.jdk.CollectionConverters.{ListHasAsScala, MapHasAsScala}

trait HardwareWalletInterface {
  this: Service with EclairDirectives =>

  import HardwareWalletInterface._

  import fr.acinq.eclair.api.serde.JsonSupport.{formats, marshaller, serialization}

  val enumerate: Route = postRequest("enumerate") { implicit t =>
    val json = new JObject(List(
      "type" -> JString("eclair"),
      "model" -> JString("eclair"),
      "label" -> JString(""),
      "path" -> JString(""),
      "fingerprint" -> JString(DeterministicWallet.fingerprint(master).toHexString),
      "needs_pin_sent" -> JBool(false),
      "needs_passphrase_sent" -> JBool(false)
    ))
    complete(List(json))
  }

  val getmasterxpub: Route = postRequest("getmasterxpub") { implicit t =>
    val xpub = DeterministicWallet.encode(DeterministicWallet.publicKey(master), DeterministicWallet.xpub)
    complete(new JObject(List("xpub" -> JString(xpub))))
  }

  val getdescriptors: Route = postRequest("getdescriptors") { implicit t =>
    val accountPub = publicKey(derivePrivateKey(master, KeyPath("84'/1'/0'/0")))
    val accountDesc = s"wpkh([${fingerprint(master).toHexString}/84h/1h/0h/0]${encode(accountPub, tpub)}/0/*)"
    val changeDesc = s"wpkh([${fingerprint(master).toHexString}/84h/1h/0h/1]${encode(accountPub, tpub)}/1/*)"
    val json = new JObject(List(
      "receive" -> JArray(List(JString(s"$accountDesc#${descriptorChecksum(accountDesc)}"))),
      "internal" -> JArray(List(JString(s"$changeDesc#${descriptorChecksum(changeDesc)}")))
    ))
    complete(json)
  }

  val signtx: Route = postRequest("signtx") { implicit t =>
    formFields("psbt".as[String]) { base64 =>
      val psbt = Psbt.read(Base64.getDecoder.decode(base64)).getRight
      logger.info { s"signing $psbt"}
      val psbt1 = signPsbt(master, psbt)
      val json = new JObject(List("psbt" -> JString(Base64.getEncoder.encodeToString(Psbt.write(psbt1).toByteArray))))
      complete(json)
    }
  }

  val hwiRoute = enumerate ~ getmasterxpub ~ getdescriptors ~ signtx
}

object HardwareWalletInterface {
  val mnemonics = "book mandate inside morning lucky result cruel other frame dragon property chimney"
  val seed = MnemonicCode.toSeed(mnemonics, "")
  val master = DeterministicWallet.generate(seed)

  def polyMod(cc: Long, value: Int): Long = {
    var c = cc;
    val c0 = c >> 35;
    c = ((c & 0x7ffffffffL) << 5) ^ value
    if ((c0 & 1L) != 0) c = c ^ 0xf5dee51989L
    if ((c0 & 2L) != 0) c = c ^ 0xa9fdca3312L
    if ((c0 & 4L) != 0) c = c ^ 0x1bab10e32dL
    if ((c0 & 8L) != 0) c = c ^ 0x3706b1677aL
    if ((c0 & 16L) != 0) c = c ^ 0x644d626ffdL
    c
  }

  def descriptorChecksum(span: String): String = {
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    val INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

    /** The character set for the checksum itself (same as bech32). */
    val CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    var c = 1L;
    var cls = 0;
    var clscount = 0;
    span.foreach(ch => {
      val pos = INPUT_CHARSET.indexOf(ch);
      if (pos == -1) return "";
      c = polyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
      cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
      clscount = clscount + 1
      if (clscount == 3) {
        // Emit an extra symbol representing the group numbers, for every 3 characters.
        c = polyMod(c, cls);
        cls = 0;
        clscount = 0;
      }
    })
    if (clscount > 0) c = polyMod(c, cls);
    for (j <- 0 until 8) c = polyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    var ret = "        "
    for (j <- 0 until 8) {
      val pos1 = (c >> (5 * (7 - j))) & 31
      val char = CHECKSUM_CHARSET.charAt(pos1.toInt);
      ret = ret.updated(j, char)
    }
    ret
  }

  def signPsbt(master: ExtendedPrivateKey, psbt: Psbt): Psbt = {
    import fr.acinq.bitcoin.{SigHash, SigVersion, Script, Transaction}
    var psbt1 = psbt
    for (pos <- 0 until psbt.getInputs.size()) {
      val input = psbt.getInput(pos)
      input.getDerivationPaths.asScala.foreach { case (pub, keypath) =>
        val priv = fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey(master.priv, keypath.getKeyPath).getPrivateKey
        val check = priv.publicKey()
        assert(check == pub)
        assert(Script.isPay2wpkh(input.getWitnessUtxo.publicKeyScript.toByteArray))
        // TODO: we don't use Psbt.sign() here because it does not handle p2wpkh inputs very well, update when this is fixed
        val sig = Transaction.signInput(psbt.getGlobal.getTx, pos, Script.pay2pkh(pub), SigHash.SIGHASH_ALL, input.getWitnessUtxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv)
        psbt1 = psbt1.finalizeWitnessInput(pos, new ScriptWitness().push(sig).push(pub.value)).getRight
      }
    }
    psbt1
  }
}