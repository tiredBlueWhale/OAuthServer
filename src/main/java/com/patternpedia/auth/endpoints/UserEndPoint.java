package com.patternpedia.auth.endpoints;


import com.patternpedia.auth.user.entities.UserEntity;
import com.patternpedia.auth.user.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Controller
public class UserEndPoint {

    private final UserRepository userRepository;

    public UserEndPoint(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @RequestMapping(method = RequestMethod.GET, value = "/user_info")
    @ResponseBody
    public Map<String, Object> user(@AuthenticationPrincipal Principal principal) {
        if (principal != null) {
            UUID id = UUID.fromString(principal.getName());
            UserEntity user = userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found: " + principal.getName()));
            Map<String, Object> model = new HashMap<String, Object>();
//            model.put("email", user.getEmail());
            model.put("name", user.getName());
            model.put("id", user.getId());
            model.put("role", user.getRole().getName());
            model.put("privileges", user.getRole().getPrivileges().stream().map(privilege -> privilege.getName()).collect(Collectors.toList()));
            return model;
        }
        return null;
    }
}
