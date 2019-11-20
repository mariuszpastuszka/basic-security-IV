package workshop.sb.security.basics.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import workshop.sb.security.basics.model.User;
import workshop.sb.security.basics.repository.UserRepository;

import javax.validation.Valid;

@Controller
@RequestMapping("/")
public class UserController {

    private final UserRepository userRepository;

    @Autowired
    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping
    public ModelAndView list() {
        Iterable<User> users = this.userRepository.findAll();
        return new ModelAndView("users/list", "users", users);
    }

    @GetMapping("{id}")
    public ModelAndView view(@PathVariable("id") User user) {
        return new ModelAndView("users/view", "user", user);
    }

    @GetMapping(params = "form")
    public ModelAndView createForm(@ModelAttribute User user) {
        return new ModelAndView("users/form", "user", user);
    }

    @PostMapping
    public ModelAndView create(@Valid User user, BindingResult result, RedirectAttributes redirect) {
        if (result.hasErrors()) {
            return new ModelAndView("users/form", "formErrors", result.getAllErrors());
        }
        user = this.userRepository.save(user);
        redirect.addFlashAttribute("globalMessage", "Successfully created a new user");
        return new ModelAndView("redirect:/{user.id}", "user.id", user.getId());
    }

    @GetMapping(value = "delete/{id}")
    public ModelAndView delete(@PathVariable("id") Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        this.userRepository.deleteById(id);
        return new ModelAndView("redirect:/");
    }

    @GetMapping("modify/{id}")
    public ModelAndView modifyForm(@PathVariable("id") User user) {
        return new ModelAndView("users/form", "user", user);
    }

}
