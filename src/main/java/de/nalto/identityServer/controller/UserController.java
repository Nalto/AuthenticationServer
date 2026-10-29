package de.nalto.identityServer.controller;

import de.nalto.identityServer.exceptions.UserNotFoundException;
import de.nalto.identityServer.exceptions.UserUpdateException;
import de.nalto.identityServer.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/user")
public class UserController {

    private static final String CURRENT_USER_URL = "redirect:/user/current";

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    public String user(Model model, @PathVariable("id") Long id, @AuthenticationPrincipal UserDetails user) {
        if (user.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You are not allowed to view this page");
        }
        try {
            model.addAttribute("user", userService.getUser(id));
            model.addAttribute("editable", false);
        } catch (UserNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        }
        return "user";
    }

    @GetMapping("/current")
    public String currentUser(Model model, @AuthenticationPrincipal UserDetails user) {
        try {
            model.addAttribute("user", userService.getUserInfo(user.getUsername()));
            model.addAttribute("editable", true);
            return "user";
        } catch (UserNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Current user not found");
        }
    }

    @PostMapping("/current/email")
    public String updateEmail(@AuthenticationPrincipal UserDetails user,
                              @RequestParam("email") String email,
                              RedirectAttributes redirectAttributes) {
        try {
            userService.updateEmail(user.getUsername(), email);
            redirectAttributes.addFlashAttribute("success", "user.updated");
        } catch (UserUpdateException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
        } catch (UserNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Current user not found");
        }
        return CURRENT_USER_URL;
    }

    @PostMapping("/current/username")
    public String updateUsername(@AuthenticationPrincipal UserDetails user,
                                 @RequestParam("username") String username,
                                 Authentication authentication,
                                 HttpServletRequest request,
                                 HttpServletResponse response,
                                 RedirectAttributes redirectAttributes) {
        try {
            userService.updateUsername(user.getUsername(), username);
        } catch (UserUpdateException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
            return CURRENT_USER_URL;
        } catch (UserNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Current user not found");
        }
        if (username.equals(user.getUsername())) {
            return CURRENT_USER_URL;
        }
        // The session is bound to the old username, so the user has to log in again.
        new SecurityContextLogoutHandler().logout(request, response, authentication);
        return "redirect:/login";
    }

    @PostMapping("/current/password")
    public String updatePassword(@AuthenticationPrincipal UserDetails user,
                                 @RequestParam("currentPassword") String currentPassword,
                                 @RequestParam("newPassword") String newPassword,
                                 RedirectAttributes redirectAttributes) {
        try {
            userService.updatePassword(user.getUsername(), currentPassword, newPassword);
            redirectAttributes.addFlashAttribute("success", "user.updated");
        } catch (UserUpdateException e) {
            redirectAttributes.addFlashAttribute("error", e.getMessage());
        } catch (UserNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Current user not found");
        }
        return CURRENT_USER_URL;
    }
}
