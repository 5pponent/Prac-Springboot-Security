package prac.security.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import prac.security.security.config.auth.PrincipalDetails;
import prac.security.security.model.User;
import prac.security.security.repository.UserRepository;

@Controller
@RequiredArgsConstructor
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    // Argument 로 유저 정보 받아오기
    public String loginTest(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication.getPrincipal() = " + principalDetails.getUser());
        System.out.println("userDetails.getUsername() = " + userDetails.getUser());
        return "Authentication, @AuthenticationPrincipal Argument 로 유저 정보 받아오기";
    }

    @GetMapping("/test/login-oauth")
    @ResponseBody
    // OAuth 인증으로 가입한 유저는 OAuth2User 로 캐스팅하여 받아야 함
    // 근데 PrincipalDetails 가 UserDetails, OAuth2User 의 구현체라서 해당 객체로 받으면 됨
    public String oauthLoginTest(Authentication authentication, @AuthenticationPrincipal OAuth2User userDetails) {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
        System.out.println("userDetails.getAttributes() = " + userDetails.getAttributes());
        return "OAuth 를 통해 로그인한 유저의 정보 받아오기 " + oAuth2User.getAttributes();
    }

    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    // PrincipalDetails 로 통일하여 유저 정보를 받아오기
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails.getUser() = " + principalDetails.getUser());
        return principalDetails.getUser().toString();
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/login-form")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/join-form")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("ROLE_USER");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/login-form";
    }

    @GetMapping("/info")
    @ResponseBody
    @Secured("ROLE_ADMIN")
    // SecurityConfig 에서 EnableGlobalMethodSecurity 어노테이션에 
    // SecuredEnabled = true 로 설정해서 Secured 어노테이션 사용 가능
    // 메소드에 직접 요청 가능한 권한 설정 가능
    public String info() {
        return "개인정보";
    }

    @GetMapping("/data")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    // SecurityConfig 에서 EnableGlobalMethodSecurity 어노테이션에
    // prePostEnabled = true 로 설정해서 PreAuthorize 어노테이션 사용 가능
    // 메소드에 직접 요청 가능한 권한 설정 가능
    public String data() {
        return "데이터";
    }
}
