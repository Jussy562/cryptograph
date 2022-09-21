import { useState } from "react"

const generatekey = async () => {
  let keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  )
  return keyPair
}

function getMessageEncoding(text) {
  let enc = new TextEncoder()
  return enc.encode(text)
}

function encryptMessage(publicKey, text) {
  let encoded = getMessageEncoding(text)
  return window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    encoded,
  )
}

export async function copyTextToClipboard(text) {
  if ("clipboard" in navigator) {
    return await navigator.clipboard.writeText(text)
  } else {
    return document.execCommand("copy", true, text)
  }
}

function decryptMessageWithKey(privateKey, ciphertext) {
  return window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, ciphertext)
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf))
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

function importPrivateKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----"
  const pemFooter = "-----END PRIVATE KEY-----"
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents)
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString)

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"],
  )
}

async function exportCryptoKey(key) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", key)
  const exportedAsString = ab2str(exported)
  const exportedAsBase64 = window.btoa(exportedAsString)
  return exportedAsBase64
}

export default function Home() {
  const [encrytMessage, setEncryptMessage] = useState("")
  const [isProcessing, setIsProcessing] = useState(false)
  const [activeMenu, setActiveMenu] = useState("encode")
  const [privateKey, setPrivateKey] = useState("")

  //decipher states
  const [decryptKey, setDecryptKey] = useState("")
  const [isDecrypting, setIsDecrypting] = useState(false)
  const [decryptMessage, setDecryptMessage] = useState("")

  //functions
  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!encrytMessage) return
    setIsProcessing(true)
    const key = await generatekey()
    const buffer = await encryptMessage(key.publicKey, encrytMessage)
    let ciphertext = ab2str(buffer)
    let base64Cipher = window.btoa(ciphertext)
    let hashtext = await exportCryptoKey(key.privateKey)
    setPrivateKey(hashtext)
    setEncryptMessage(base64Cipher)
    setIsProcessing(false)
  }

  const handleDecryption = async (e) => {
    e.preventDefault()
    if (!decryptMessage || !decryptKey) return
    setIsDecrypting(true)
    let pem = `-----BEGIN PRIVATE KEY-----
    ${decryptKey}
    -----END PRIVATE KEY-----`
    let hashtext = await importPrivateKey(pem)
    let ciphertext = window.atob(decryptMessage)
    let base64Cipher = str2ab(ciphertext)
    const decipher = await decryptMessageWithKey(hashtext, base64Cipher)
    setDecryptMessage(ab2str(decipher))
    setDecryptKey("")
    setIsDecrypting(false)
  }
  const handleReset = () => {
    setPrivateKey("")
    setEncryptMessage("")
    setDecryptMessage("")
    setDecryptKey("")
    setActiveMenu("encode")
  }
  const handleCopyKey = async () => {
    await copyTextToClipboard(privateKey)
    alert(`key copied successfully`)
  }

  const handleCopyMessage = async () => {
    await copyTextToClipboard(encrytMessage)
    alert(`message copied successfully`)
  }

  return (
    <div className="flex flex-col w-screen min-h-screen p-6">
      <header className="flex items-center justify-between w-full h-12 px-4 border-4">
        <div>Peace ENcrypt</div>
        <div className="flex items-center space-x-5">
          <button onClick={() => setActiveMenu("encode")} className={activeMenu === "encode" ? "text-green-500 " : ""}>
            Encode
          </button>
          <button onClick={() => setActiveMenu("decode")} className={activeMenu === "decode" ? "text-green-500 " : ""}>
            Decode
          </button>
        </div>
      </header>
      <div className="flex-1 w-full p-4 border-4">
        {activeMenu === "encode" && (
          <form className="flex flex-col w-full space-y-3" onSubmit={handleSubmit}>
            {privateKey && <p>copy your encrypted message and key</p>}
            {privateKey && (
              <div className="flex items-center justify-between p-4 border">
                <p className="flex-1 w-full break-words truncate">{privateKey}</p>
                <button onClick={handleCopyKey} className="px-4 border rounded h-11" type="button">
                  click to copy key
                </button>
              </div>
            )}
            <textarea
              className="w-full p-4 border outline-none"
              rows={15}
              value={encrytMessage}
              onChange={({ target }) => setEncryptMessage(target.value)}
              placeholder="Enter a message to encrypt"
            />
            {!!!privateKey ? (
              <button disabled={isProcessing} className="px-4 border rounded h-11" type="submit">
                {isProcessing ? "encrypting..." : "Encrypt"}
              </button>
            ) : (
              <div onClick={handleCopyMessage} className="flex space-x-6">
                <button className="px-4 border rounded h-11" type="button">
                  copy encrypted message
                </button>
                <button onClick={handleReset} className="px-4 border rounded h-11">
                  reset
                </button>
              </div>
            )}
          </form>
        )}
        {activeMenu === "decode" && (
          <form className="flex flex-col w-full space-y-3" onSubmit={handleDecryption}>
            {privateKey && <p>paste your encrypted message and key</p>}

            <input
              onChange={({ target }) => setDecryptKey(target.value)}
              value={decryptKey}
              type={"text"}
              placeholder="paste your encryption key here"
              className="w-full px-4 border rounded outline-none h-11"
            />
            <textarea
              className="w-full p-4 border outline-none"
              rows={15}
              value={decryptMessage}
              onChange={({ target }) => setDecryptMessage(target.value)}
              placeholder="Enter a message to decrypt"
            />

            {!!decryptKey ? (
              <button disabled={isDecrypting} className="px-4 border rounded h-11" type="submit">
                {isDecrypting ? "decrypting..." : " Decrypt messsage"}
              </button>
            ) : (
              <button onClick={handleReset} className="px-4 border rounded h-11" type="button">
                reset
              </button>
            )}
          </form>
        )}
      </div>
    </div>
  )
}
