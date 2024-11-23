package com.devops.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder routeLocatorBuilder){
        return routeLocatorBuilder.routes()
                .route("user-service-api-1", r -> r.path("/user-service/**")
                        .uri("http://localhost:8001"))
                .route("product-service-api-2", r -> r.path("/product-service/**")
                        .uri("http://localhost:8002"))
                .route("order-service-api-3", r -> r.path("/order-service/**")
                        .uri("http://localhost:8003"))
                .build();
    }
}
