package com.komou.app.secure;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

@Service
public class SecurityService {

    @Value("${app.security.api-keys}")
    private Set<String> validApiKeys;

    @Value("${app.security.hmac-secret}")
    private String hmacSecret;

    @Value("${app.security.encryption-key}")
    private String encryptionKey;

    private static final long MAX_TIME_DIFF = 5 * 60 * 1000; // 5 minutes
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public String encrypt(String data) {
        try {
            // Valider la longueur de la clé
            validateKeyLength(encryptionKey, 32);

            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);

        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Encryption failed: " + e.getMessage());
        }
    }

    public String decrypt(String encryptedData) {
        try {
            // Valider la longueur de la clé
            validateKeyLength(encryptionKey, 32);

            // Vérifier que les données ne sont pas vides
            if (encryptedData == null || encryptedData.trim().isEmpty()) {
                throw new IllegalArgumentException("Encrypted data is empty");
            }

            // Décoder Base64 d'abord
            byte[] encryptedBytes;
            try {
                encryptedBytes = Base64.getDecoder().decode(encryptedData.trim());
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid Base64 encoding");
            }

            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (javax.crypto.BadPaddingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Decryption failed: Bad padding - check encryption key and data integrity");
        } catch (javax.crypto.IllegalBlockSizeException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Decryption failed: Illegal block size - data may be corrupted");
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Decryption failed: " + e.getMessage());
        }
    }

    private void validateKeyLength(String key, int expectedLength) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        if (key.getBytes(StandardCharsets.UTF_8).length != expectedLength) {
            throw new IllegalArgumentException(
                    "Key must be exactly " + expectedLength + " bytes, got " +
                            key.getBytes(StandardCharsets.UTF_8).length + " bytes");
        }
    }

    // Le reste du service reste identique...
    public String generateSignature(Long timestamp, String encryptedData, String apiKey) {
        try {
            String message = timestamp + "." + encryptedData + "." + apiKey;
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);

            byte[] hmacBytes = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Signature generation failed");
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public void validateRequest(String encryptedData, Long timestamp, String signature, String apiKey) {
        if (!validApiKeys.contains(apiKey)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid API key");
        }

        long currentTime = System.currentTimeMillis();
        long timeDiff = Math.abs(currentTime - timestamp);

        if (timeDiff > MAX_TIME_DIFF) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Request timestamp expired");
        }

        String expectedSignature = generateSignature(timestamp, encryptedData, apiKey);
        if (!signature.equals(expectedSignature)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid signature");
        }
    }

    public SecureResponseDto prepareSecureResponse(Object data) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            String jsonData = mapper.writeValueAsString(data);

            String encryptedData = encrypt(jsonData);
            return new SecureResponseDto(encryptedData, System.currentTimeMillis());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Response preparation failed");
        }
    }

    // Chiffrement AES
//    public String encrypt(String data) {
//        try {
//            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), ALGORITHM);
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//            byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
//            return Base64.getEncoder().encodeToString(encryptedBytes);
//        } catch (Exception e) {
//            System.err.println("encrypt error ==> " + e.getMessage());
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Encryption failed");
//        }
//    }
//
//    // Déchiffrement AES
//    public String decrypt(String encryptedData) {
//        try {
//            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), ALGORITHM);
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//            cipher.init(Cipher.DECRYPT_MODE, secretKey);
//            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
//            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
//            return new String(decryptedBytes, StandardCharsets.UTF_8);
//        } catch (Exception e) {
//            System.err.println("decrypt error ==> " + e.getMessage());
//            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Decryption failed");
//        }
//    }
//
//    // Génération de signature HMAC
//    public String generateSignature(Long timestamp, String encryptedData, String apiKey) {
//        String message = timestamp + "." + encryptedData + "." + apiKey;
//        HmacUtils hmacUtils = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, hmacSecret);
//        return hmacUtils.hmacHex(message);
//    }
//
//    // Validation de la requête
//    public void validateRequest(String encryptedData, Long timestamp, String signature, String apiKey) {
//        // Validation API Key
//        if (!validApiKeys.contains(apiKey)) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid API key");
//        }
//
//        // Validation timestamp
//        long currentTime = System.currentTimeMillis();
//        long timeDiff = Math.abs(currentTime - timestamp);
//
//        if (timeDiff > MAX_TIME_DIFF) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Request timestamp expired");
//        }
//
//        // Validation signature
//        String expectedSignature = generateSignature(timestamp, encryptedData, apiKey);
//        if (!signature.equals(expectedSignature)) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid signature");
//        }
//    }
//
//    // Traitement de la requête sécurisée
//    public JSONObject processSecureRequest(SecureRequestDto secureRequest, String signature, String apiKey) {
//        validateRequest(secureRequest.getData(), secureRequest.getTimestamp(), signature, apiKey);
//
//        String decryptedData = decrypt(secureRequest.getData());
//        return new JSONObject(decryptedData);
//    }
//
//    // Préparation de la réponse sécurisée
//    public SecureResponseDto prepareSecureResponse(Object data) {
//        String jsonData = new JSONObject(data).toString();
//        String encryptedData = encrypt(jsonData);
//        return new SecureResponseDto(encryptedData, System.currentTimeMillis());
//    }
}