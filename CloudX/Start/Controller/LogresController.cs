using CloudX.DTOs;
using CloudX.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.LogReg.Controllers;

[AllowAnonymous]
public class LogRegController : Controller
{
    private const string CloudXLocalScheme = "CloudXLocal";

    private readonly ILogRegService _service;

    public LogRegController(
        ILogRegService service)
    {
        _service = service;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View(
            "~/Views/Start/Register.cshtml");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(
        RegisterDto model,
        CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            var errors =
                ModelState
                    .Values
                    .SelectMany(x => x.Errors)
                    .Select(x => x.ErrorMessage)
                    .Where(x =>
                        !string.IsNullOrWhiteSpace(x))
                    .ToList();

            return Json(new
            {
                success = false,
                message = errors.Count > 0
                    ? string.Join(" ", errors)
                    : "Please enter valid registration details."
            });
        }

        try
        {
            var result =
                await _service.RegisterAsync(
                    model,
                    cancellationToken);

            if (!result)
            {
                return Json(new
                {
                    success = false,
                    message =
                        "This email is already registered " +
                        "or the verification email could not be sent."
                });
            }

            return Json(new
            {
                success = true,
                message =
                    "Verification OTP sent successfully."
            });
        }
        catch
        {
            return Json(new
            {
                success = false,
                message =
                    "Unable to process registration right now."
            });
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> VerifyOtp(
        string email,
        string otp,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return Json(new
            {
                success = false,
                message = "Email is required."
            });
        }

        if (string.IsNullOrWhiteSpace(otp))
        {
            return Json(new
            {
                success = false,
                message = "OTP is required."
            });
        }

        try
        {
            var result =
                await _service.VerifyOtpAsync(
                    email,
                    otp,
                    cancellationToken);

            if (!result)
            {
                return Json(new
                {
                    success = false,
                    message =
                        "Invalid or expired OTP."
                });
            }

            return Json(new
            {
                success = true,
                message =
                    "Email verified successfully."
            });
        }
        catch
        {
            return Json(new
            {
                success = false,
                message =
                    "Unable to verify OTP right now."
            });
        }
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View(
            "~/Views/Start/Login.cshtml");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(
        LoginDto model,
        CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Json(new
            {
                success = false,
                message =
                    "Please enter a valid email and password."
            });
        }

        try
        {
            var user =
                await _service.LoginAsync(
                    model.Email,
                    model.Password,
                    cancellationToken);

            if (user == null)
            {
                return Json(new
                {
                    success = false,
                    message =
                        "Invalid email or password."
                });
            }

            var claims = new List<Claim>
            {
                new Claim(
                    ClaimTypes.NameIdentifier,
                    user.Id.ToString()),

                new Claim(
                    ClaimTypes.Email,
                    user.Email),

                new Claim(
                    ClaimTypes.Name,
                    user.Email),

                new Claim(
                    ClaimTypes.Role,
                    user.Role)
            };

            var identity =
                new ClaimsIdentity(
                    claims,
                    CloudXLocalScheme);

            var principal =
                new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CloudXLocalScheme,
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc =
                        DateTimeOffset.UtcNow.AddHours(8)
                });

            return Json(new
            {
                success = true,
                message =
                    "Login successful."
            });
        }
        catch
        {
            return Json(new
            {
                success = false,
                message =
                    "Unable to process login right now."
            });
        }
    }

    [HttpGet]
    public IActionResult Dashboard()
    {
        return View(
            "~/Views/Start/Dashboard.cshtml");
    }

    [HttpGet]
    public IActionResult ConnectAzure()
    {
        return View(
            "~/Views/AzureConnection/ConnectAzure.cshtml");
    }
}