package prac.security.security.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import prac.security.security.config.auth.PrincipalDetails;
import prac.security.security.model.User;
import prac.security.security.repository.UserRepository;

@Service
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    /**
     * 구글로부터 받은 userRequest 에 대한 후처리 로직
     * 구글 로그인 버튼 클릭
     * -> 구글 로그인 창, 로그인 완료
     * -> 코드 발급
     * -> OAuth2-Client 라이브러리가 해당 코드로 엑세스 토큰을 발급받음
     * -> 해당 토큰으로 구글 회원 프로필 받아옴
     * -> userRequest 객체 바인딩, loadUser 함수 호출
     * -> 구글 인증 완료 후처리 로직 작성
     * userRequest: 액세스 토큰을 통해 얻은 정보를 가지고 있음
     */
    // 함수 종료 시 @AuthenticationPrincipal 어노테이션 생성
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken().getTokenValue());
        System.out.println("userRequest.getAdditionalParameters() = " + userRequest.getAdditionalParameters());
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println("user.getAttributes() = " + oAuth2User.getAttributes());

        // 회원가입 로직
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        }
        else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }
        else { System.out.println("지원하지 않는 플랫폼"); }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = passwordEncoder.encode("비밀번호");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);
        if (user == null) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(user);
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }
}