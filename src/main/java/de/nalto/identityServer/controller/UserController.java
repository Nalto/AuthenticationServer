package de.nalto.identityServer.controller;

import de.nalto.identityServer.dto.UserDetails;
import de.nalto.identityServer.persistence.model.User;
import de.nalto.identityServer.services.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("{id}")
    public String user(Model model, @PathVariable("id") Long id) {
        model.addAttribute("user", userService.getUser(id));
        return "user";
    }

    @GetMapping("")
    public String currentUser(Model model, @AuthenticationPrincipal User user) {
        model.addAttribute("user", new UserDetails(user.getId(), user.getUsername()));
        return "user";
    }
}
