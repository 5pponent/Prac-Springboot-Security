package prac.security.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import prac.security.security.config.oauth.PrincipalOAuth2UserService;

@Configuration
@EnableWebSecurity // 시큐리티 필터를 스프링 필터 체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// securedEnabled : Secured 어노테이션 사용 여부
// prePostEnabled : preAuthorize, postAuthorize 어노테이션 사용 여부
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOAuth2UserService principalOAuth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                /**
                 * URI 접근 권한 설정
                 */
                // /user/** : 인증 필요
                .antMatchers("/user/**").authenticated()
                // /manager/** : Admin 또는 Manager 권한 필요
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                // /admin/** : Admin 권한 필요
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 이 외 모든 uri 요청 허용
                .anyRequest().permitAll() // 이 외 url 전부 인증 없이 요청 가능

                /**
                 * 기본 로그인 설정
                 */
                .and()
                .formLogin()
                .loginPage("/login-form")
                .loginProcessingUrl("/login") // 시큐리티가 로그인을 진행할 URL 설정
                .defaultSuccessUrl("/")

                /**
                 * OAuth2 구글 로그인/회원가입 설정
                 * 회원 가입 시
                 * 구글 로그인을 통해 코드(인증 완료), 액세스 토큰 발급(구글 계정 접근 권한)
                 * -> 토큰으로 사용자 프로필 받아옴
                 * -> 해당 정보를 바탕으로 회원가입 진행 or 추가 정보 입력 받아서 회원가입 진행
                 * 로그인 시
                 * 구글 로그인을 통해 엑세스 토큰 + 사용자 프로필 받아옴
                 */
                .and()
                .oauth2Login()
                .loginPage("/login-form")
                .userInfoEndpoint()
                .userService(principalOAuth2UserService);
    }
}
