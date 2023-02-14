package io.oauth.authorizationserver.controller;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.domain.UserJoinDto;
import io.oauth.authorizationserver.domain.UserLoginDto;
import io.oauth.authorizationserver.service.UserService;
import io.oauth.authorizationserver.utils.DecryptUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

@Slf4j
@Controller
public class UserController {

    private final UserService userService;
    private final KeyPair keyPair;
    private final PasswordEncoder passwordEncoder;
    private static String modulus;
    private static String exponent;


    public UserController(UserService userService, KeyPair keyPair, PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.userService = userService;
        this.keyPair = keyPair;
        this.passwordEncoder = passwordEncoder;
        publicKey();
    }

    @GetMapping("/login")
    public String login(@RequestParam(value="error", required = false) String error,
                        @RequestParam(value="message", required = false) String message
                        , Model model) throws NoSuchAlgorithmException, InvalidKeySpecException {
        model.addAttribute("user", new UserLoginDto());
        model.addAttribute("error", error);
        model.addAttribute("message", message);
        model.addAttribute("modulus", modulus);
        model.addAttribute("exponent", exponent);
        return "login";
    }

    private void publicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicSpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        modulus = publicSpec.getModulus().toString(16);
        exponent = publicSpec.getPublicExponent().toString(16);
    }

    @GetMapping("/join")
    public String join(Model model){
        model.addAttribute("user", new UserJoinDto());
        model.addAttribute("modulus", modulus);
        model.addAttribute("exponent", exponent);
        return "join";
    }

    @PostMapping("/join")
    public String join(@Validated @ModelAttribute("user") UserJoinDto userJoinDto, BindingResult bindingResult, Model model) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if(bindingResult.hasErrors()){
            log.info(bindingResult.getAllErrors().toString());
            model.addAttribute("modulus", modulus);
            model.addAttribute("exponent", exponent);
            return "/join";
        }
        String encryptedPassword = DecryptUtils.decryptValueRsa((RSAPrivateKey) keyPair.getPrivate(), userJoinDto.getPassword());
        userJoinDto.setPassword(passwordEncoder.encode(encryptedPassword));
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

}
