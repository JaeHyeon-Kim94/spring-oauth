package io.oauth.authorizationserver.controller;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.domain.UserJoinDto;
import io.oauth.authorizationserver.domain.UserLoginDto;
import io.oauth.authorizationserver.service.UserService;
import io.oauth.authorizationserver.utils.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

@Slf4j
@Controller
public class UserController {

    private static final String PRIVATE_KEY_NAME = "__RSA_WEB_Key_";

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserService userService, PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }


    @GetMapping("/login")
    public String login(@RequestParam(value="error", required = false) String error,
                        @RequestParam(value="message", required = false) String message
                        , Model model
                        , HttpSession session) throws NoSuchAlgorithmException, InvalidKeySpecException {
        model.addAttribute("user", new UserLoginDto());
        model.addAttribute("error", error);
        model.addAttribute("message", message);

        setModelAndSessionRsaKey(model, session);

        return "login";
    }

    @GetMapping("/join")
    public String join(Model model, HttpSession session) throws NoSuchAlgorithmException, InvalidKeySpecException {
        model.addAttribute("user", new UserJoinDto());
        setModelAndSessionRsaKey(model, session);
        return "join";
    }



    @PostMapping("/join")
    public String join(@Validated @ModelAttribute("user") UserJoinDto userJoinDto, BindingResult bindingResult, Model model, HttpSession session) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        if(bindingResult.hasErrors()){
            log.info(bindingResult.getAllErrors().toString());
            setModelAndSessionRsaKey(model, session);
            return "/join";
        }


        PrivateKey privateKey = (PrivateKey) session.getAttribute(PRIVATE_KEY_NAME);
        if(privateKey == null){
            throw new RuntimeException("암호화 비밀키 정보를 찾을 수 없음.");
        }
        session.removeAttribute(PRIVATE_KEY_NAME);

        String password = userJoinDto.getPassword();
        try {
            password = RSAUtil.decryptValueRsa(privateKey, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        userJoinDto.setPassword(passwordEncoder.encode(password));
        log.info("joinDto : {}", userJoinDto);
        User user = UserJoinDto.toUser(userJoinDto);
        userService.save(user);

        return "redirect:/login";
    }

    @GetMapping("/members/{type}/{value}/check-duplicated")
    public @ResponseBody ResponseEntity<Boolean> isDuplicatedNickname(@PathVariable String type, @PathVariable String value){

        if(!type.equals("nickname") && !type.equals("username")){
            throw new IllegalArgumentException("Invalid type. only nickname or username");
        }

        boolean result = userService.checkIsDuplicated(type, value);

        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    private void setModelAndSessionRsaKey(Model model, HttpSession session) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Map<String, Object> keys = RSAUtil.getRSAKeys();

        model.addAttribute("modulus", (String)keys.get("modulus"));
        model.addAttribute("exponent", (String)keys.get("exponent"));
        session.setAttribute(PRIVATE_KEY_NAME, (PrivateKey)(keys.get(PRIVATE_KEY_NAME)));
    }

}
