package com.komou.app.user;

import com.komou.app.secure.SecureRequestDto;
import com.komou.app.secure.SecureResponseDto;
import com.komou.app.secure.SecurityService;
import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/secure")
public class SecureUserController {

    private final SecurityService securityService;

    private final UserService userService;

    public SecureUserController(SecurityService securityService, UserService userService) {
        this.securityService = securityService;
        this.userService = userService;
    }

    @PostMapping("/users")
    public ResponseEntity<SecureResponseDto> createUser(
            @RequestHeader("X-API-Key") String apiKey,
            @RequestHeader("X-Signature") String signature,
            @RequestHeader("X-Timestamp") Long timestamp,
            @RequestBody SecureRequestDto secureRequest) {
        System.err.println("apiKey ==> " + apiKey);
        System.err.println("signature ==> " + signature);
        System.err.println("timestamp ==> " + timestamp);
        try {
            securityService.validateRequest(secureRequest.getData(), timestamp, signature, apiKey);
            String decryptedData = securityService.decrypt(secureRequest.getData());
            JSONObject userData = new JSONObject(decryptedData);

            // Traitement des données utilisateur
            User user = userService.createUser(userData);

            // Réponse sécurisée
            SecureResponseDto secureResponse = securityService.prepareSecureResponse(user);
            return ResponseEntity.ok(secureResponse);

        } catch (Exception e) {
            System.err.println(e);
            SecureResponseDto errorResponse = securityService.prepareSecureResponse(
                    new JSONObject().put("error", e.getMessage())
            );
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<SecureResponseDto> getUser(@PathVariable String id, HttpServletRequest request) {
        try {
            User user = userService.getUserById(id);

            SecureResponseDto secureResponse = securityService.prepareSecureResponse(user);
            return ResponseEntity.ok(secureResponse);

        } catch (Exception e) {
            SecureResponseDto errorResponse = securityService.prepareSecureResponse(
                    new JSONObject().put("error", e.getMessage())
            );
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<SecureResponseDto> updateUser(@PathVariable String id, HttpServletRequest request) {
        try {
            String decryptedBody = (String) request.getAttribute("decryptedBody");
            JSONObject userData = new JSONObject(decryptedBody);

            User updatedUser = userService.updateUser(id, userData);

            SecureResponseDto secureResponse = securityService.prepareSecureResponse(updatedUser);
            return ResponseEntity.ok(secureResponse);

        } catch (Exception e) {
            SecureResponseDto errorResponse = securityService.prepareSecureResponse(
                    new JSONObject().put("error", e.getMessage())
            );
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
}