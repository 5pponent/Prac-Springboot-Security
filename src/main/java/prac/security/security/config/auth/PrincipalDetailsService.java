package prac.security.security.config.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import prac.security.security.model.User;
import prac.security.security.repository.UserRepository;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login 요청 시 자동으로 UserDetailsService 타입으로 loadUserByUsername 실행
// 흐름: /login -> 시큐리티에서 로그인 처리 -> loadUserByUsername -> User 엔티티 return
// -> Authentication 에 return 받은 User 엔티티 바인딩
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 함수 종료 시 @AuthenticationPrincipal 어노테이션 생성
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user != null) {
            return new PrincipalDetails(user);
        }
        return null;
    }
}
