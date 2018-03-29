package com.junjin.community.com.junjin.community.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import lombok.extern.java.Log;

@Log
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


	@Autowired
	@Qualifier("dataSource")
	DataSource dataSource;

	@Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/resources/**/**");
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		log.info("hi");
		log.info("security config..............");
		//http.authorizeRequests().antMatchers("/dist/img/**").permitAll();
		http.authorizeRequests().antMatchers("/**/**").permitAll();
		http.csrf().disable();
		
		//http.formLogin().loginPage("/login");
		//http.exceptionHandling().accessDeniedPage("/accessDenied");
		//http.logout().logoutUrl("/logout").invalidateHttpSession(true);
	}

	

	
}
