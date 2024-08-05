package routers

import (
	advisorModule "khazande/internal/advisor"
	handlersModule "khazande/internal/handlers"
	envsModule "khazande/pkg/envs"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type Router struct {
	Advisor *advisorModule.Advisor
	Handler *handlersModule.Handler
}

func Initial(envs *envsModule.Envs, logger *zap.Logger) *Router {
	return &Router{
		Advisor: &advisorModule.Advisor{
			Logger: logger,
			Envs:   envs,
		},
		Handler: handlersModule.Initial(envs, logger),
	}
}

func (r *Router) SetupRouters(app *fiber.App) {
	// Checking wether the service is up or not
	app.Get("/", func(c *fiber.Ctx) error {
		err := c.SendString("Service is up and running!")
		return err
	})

	// Adding /api as a prefix for endpoints
	api := app.Group("/api")

	api.Post("/fetch-vulnerabilities", r.Handler.VulnerabilityHandler())

	// 404 - Not Found error handler
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusNotFound).SendString("Not Found!")
	})

	app.Listen(":3000")
}
