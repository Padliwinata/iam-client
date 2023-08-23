package main

import (
	"net/http"
	"strings"

	"github.com/Padliwinata/iam-sdk"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))

	e.GET("/", func(c echo.Context) error {

		data := map[string]interface{}{
			"message": "public",
		}

		return c.JSON(http.StatusOK, data)
	})

	e.GET("/authenticated", func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			data := map[string]interface{}{
				"message": "need authorization",
			}
			return c.JSON(http.StatusUnauthorized, data)
		}

		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

		if !iam.CheckAuth(jwtToken, "$2b$04$VFIar.GWpZXLQqLk3sVoEehKdaHuU2JJoY6j5J.2g9AsHZFR8SkAu") {
			data := map[string]interface{}{
				"message": jwtToken,
			}
			return c.JSON(http.StatusUnauthorized, data)
		}

		data := map[string]interface{}{
			"message": "authenticated",
			"data": []map[string]interface{}{
				{
					"title":  "Example 1",
					"region": "First",
				},
				{
					"title":  "Example 2",
					"region": "Second",
				},
			},
		}

		return c.JSON(http.StatusOK, data)
	})

	e.GET("/authorized", func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			data := map[string]interface{}{
				"message": "need authorization",
			}
			return c.JSON(http.StatusUnauthorized, data)
		}

		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")

		if !iam.CheckAuth(jwtToken, "$2b$04$VFIar.GWpZXLQqLk3sVoEehKdaHuU2JJoY6j5J.2g9AsHZFR8SkAu") {
			data := map[string]interface{}{
				"message": "token invalid",
			}
			return c.JSON(http.StatusUnauthorized, data)
		}

		if !iam.CheckPermission(jwtToken, "$2b$04$VFIar.GWpZXLQqLk3sVoEehKdaHuU2JJoY6j5J.2g9AsHZFR8SkAu", "user:create") {
			data := map[string]interface{}{
				"message": "unauthorized",
			}
			return c.JSON(http.StatusUnauthorized, data)
		}

		data := map[string]interface{}{
			"message": "authorized",
			"data": []map[string]interface{}{
				{
					"title":  "Example 1",
					"region": "First",
					"writer": map[string]interface{}{
						"name":  "Writer 1",
						"grade": "S",
					},
				},
				{
					"title":  "Example 2",
					"region": "Second",
					"writer": map[string]interface{}{
						"name":  "Writer 2",
						"grade": "A",
					},
				},
			},
		}

		return c.JSON(http.StatusOK, data)

	})

	e.Logger.Fatal(e.Start(":8080"))
}
