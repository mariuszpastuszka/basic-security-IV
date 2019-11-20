package workshop.sb.security.basics.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authBuilder) throws Exception {
        authBuilder
                .inMemoryAuthentication()
                .withUser("user")
// {noop}password: https://stackoverflow.com/questions/46999940/spring-boot-passwordencoder-error
                .password("{noop}password")
                .roles("USER");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/webjars/**").permitAll()
                .antMatchers("/delete/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll();
            /*
                    TODO 1 użyj API dla:
                     - włączenia wylogowania (analogicznie do logowania)
                     - wylączenia CSRF (przy włączonym [zachowanie domyślne] GET nie będzie działał, tylko POST)

                       Uwaga - w tym przykładzei bawimy się API,
                       Dla produkcji, zalecany jest POST a nie GET (akcja wylogowania zmienia stan)
                 */

    }
}
