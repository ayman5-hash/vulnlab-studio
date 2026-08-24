# VulnLab Security Policy

## Purpose

VulnLab is an intentionally vulnerable web-security laboratory designed
for cybersecurity education, controlled vulnerability-detection research,
Black Box assessment, White Box assessment, and defensive security training.

## Authorized Environment Only

Run VulnLab only in an isolated and explicitly authorized environment.

The intentionally vulnerable target must not be exposed directly to the
public Internet.

## Scope Restrictions

The scanner restricts assessment targets to configured laboratory hosts
and networks.

The remote-resource laboratory is restricted to the controlled loopback
resource server running on 127.0.0.1:9000.

## Responsible Use

Only assess systems that you own or for which you have explicit
authorization.

## Security Issues

A vulnerability that allows the scanner itself to escape its intended
scope should be treated as a security defect, not as an intended
laboratory vulnerability.
