package DY.HaeDollarGo_Spring.security;

import DY.HaeDollarGo_Spring.CustomUserDetailsService;
import DY.HaeDollarGo_Spring.domain.auth.User;
import DY.HaeDollarGo_Spring.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements CustomUserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        User user = userRepository.findById(id)
                .orElseThrow(RuntimeException::new);
        return new UserDetailsImpl(user);
    }

    @Override
    public UserDetails loadUserByEmailAndSocialType(String email, String socialType) throws UsernameNotFoundException {
        User user = userRepository.findByEmailAndSocialType(email, socialType)
                .orElseThrow(RuntimeException::new);
        return new UserDetailsImpl(user);
    }
}