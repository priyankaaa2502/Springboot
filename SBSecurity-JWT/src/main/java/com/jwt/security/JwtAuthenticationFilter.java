package com.jwt.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private JwtService jwtService;

	@Autowired
	private UserDetailsService userDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain)
					throws ServletException, IOException {

		final String authHeader = request.getHeader("Authorization");
		String username=null;
		String jwt =null;

		// 1️⃣ If no Authorization header or not Bearer
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			// 2️⃣ Extract token
			jwt = authHeader.substring(7);
			// 3️⃣ Extract username from token
			username = jwtService.extractUsername(jwt);
			filterChain.doFilter(request, response);
		}



		// 4️⃣ Validate only if not already authenticated
		if (username != null) {

			UserDetails userDetails =
					userDetailsService.loadUserByUsername(username);

			// 5️⃣ Validate token properly
			if (jwtService.isTokenValid(jwt, userDetails)) {

				UsernamePasswordAuthenticationToken authToken =
						new UsernamePasswordAuthenticationToken(
								userDetails,
								null,
								userDetails.getAuthorities()
								);

				authToken.setDetails(
						new WebAuthenticationDetailsSource()
						.buildDetails(request)
						);

				// 6️⃣ Set authentication in context
				SecurityContextHolder.getContext()
				.setAuthentication(authToken);
			}
		}

		filterChain.doFilter(request, response);
	}
}