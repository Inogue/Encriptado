import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher

const val ALGORITHM = "RSA"

fun main() {
    val salida = "!"
    var salir= ""
    println("HOLA USUARIO, QUIERES ENCRIPTAR Y DESENCRIPTAR MENSAJES?")
    println("SI ES QUE SI ESCRIBE YES Y SI ES QUE NO ESCRIBE NO")
    var respuesta = readln().toUpperCase()

    val keys = generateKeys()
    val public = keys.first
    val private = keys.second

    println("ESTA ES TU CLAVE PUBLICA")
    println(public)

    while (salir!= salida) {
        if (respuesta == "YES") {
            var acabar = false
            while (acabar == false) {
             println("QUIERES ENCRIPTAR O DESENCRIPTAR?")
                println("SI QUIERES ENCRIPTAR ESCRIBE EN Y SI QUIERES DESENCRIPTAR ESCRIBE DES")
                var endes= readln().toUpperCase()
                if(endes=="EN"){
                    println("SI QUIERES ENCRIPTAR PRIMERO NECESITAS DECIRME LA CLAVE PUBLICA DEL RECEPTOR")
                val publica= readln()
                println("BIEN, AHORA DIME EL MENSAJE QUE QUIERES ENCRIPTAR")
                    val mensajen= readln()
                val encriptado=encrypt(mensajen, publica)
                    println("EL MENSAJE ENCRIPTADO ES ESTE")
                    println(encriptado)
                }
                else if(endes=="DES") {
                 println("SI QUIERES DESENCRIPTAR PRIMERO DEBES DARME EL MENSAJE ENCRIPTADO")
                    var mensaje = readln()

                try {
                    val desencriptado = decrypt(mensaje, private)
                    println("CON TU CLAVE PUBLICA HE DESENCRIPTADO EL MENSAJE, QUE ES ESTE")
                    println(desencriptado)
                }catch(e:IllegalArgumentException){
                    println("ESTA MAL, VUELVE A ESCRIBIR")
                }catch(e:BadPaddingException){
                    println("ESTA MAL, VUELVE A ESCRIBIR")
                }
                }
                else{
                    while(true) {
                    println("NO ME HAS DICHO NADA DE LO QUE TE HE PEDIDO, TE DOY OTRA OPORTUNIDAD")
                    endes = readln().toUpperCase()
                if(endes=="EN" || endes=="DES" ){
                    break
                }
                    }
                }
                println("SI QUIERES QUE ACABE EL PROGRAMA SOLO HACE FALTA QUE ESCRIBAS UN !, SI QUIERES SEGUIR DALE AL INTRO")
                salir = readln()
                if(salir=="!"){
                    acabar=true
                }
            }
        } else if (respuesta != "YES" || respuesta != "NO") {
            while (true) {
                println("TE HE DICHO QUE ESCRIBAS UN YES O UN NO")
                println("TE DOY OTRO INTENTO, QUIERES ENCRIPTAR O NO")
                respuesta = readln().toUpperCase()
                if (respuesta == "YES" || respuesta == "NO") {
                    break
                }
            }
        } else {
            println("ENTONCES AQUI ACABA ESTO")
        }

    }
}
fun generateKeys(): Pair<String, String> {
    val keyGen = KeyPairGenerator.getInstance(ALGORITHM).apply {
        initialize(512)
    }

    // Key generation
    val keys = keyGen.genKeyPair()

    // Transformation to String (well encoded)
    val publicKeyString = Base64.getEncoder().encodeToString(keys.public.encoded)
    val privateKeyString = Base64.getEncoder().encodeToString(keys.private.encoded)

    return Pair(publicKeyString, privateKeyString)
}

fun encrypt(message: String, publicKey: String): String {
    // From a String, we obtain the Public Key
    val publicBytes = Base64.getDecoder().decode(publicKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePublic(X509EncodedKeySpec(publicBytes))

    // With the public, we encrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.ENCRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(message.encodeToByteArray())
    return String(Base64.getEncoder().encode(bytes))
}

fun decrypt(encryptedMessage: String, privateKey: String): String {
    // From a String, we obtain the Private Key
    val publicBytes = Base64.getDecoder().decode(privateKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(PKCS8EncodedKeySpec(publicBytes))

    // Knowing the Private Key, we can decrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.DECRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage))
    return String(bytes)
}