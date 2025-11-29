package com.komou.app.user;

import org.springframework.stereotype.Service;

import org.json.JSONObject;

@Service
public class UserService {

    public User createUser(JSONObject userData) {
        // Implémentation de la création d'utilisateur
        User user = new User();
        user.setId(java.util.UUID.randomUUID().toString());
        user.setFirstname(userData.getString("firstname"));
        user.setLastname(userData.getString("lastname"));
        user.setAddress(userData.getString("address"));

        // Sauvegarder en base de données
        // userRepository.save(user);

        return user;
    }

    public User getUserById(String id) {
        // Récupérer de la base de données
        // return userRepository.findById(id).orElseThrow(...);

        User user = new User();
        user.setId(id);
        user.setFirstname("john_doe");
        user.setLastname("Doe");
        return user;
    }

    public User updateUser(String id, JSONObject userData) {
        // Mise à jour en base de données
        User user = getUserById(id);

        if (userData.has("firstname")) {
            user.setFirstname(userData.getString("firstname"));
        }
        if (userData.has("email")) {
            user.setLastname(userData.getString("lastname"));
        }

        if (userData.has("email")) {
            user.setAddress(userData.getString("address"));
        }

        // userRepository.save(user);
        return user;
    }

}