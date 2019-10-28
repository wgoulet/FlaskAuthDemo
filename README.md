# FlaskAuthDemo
This example app uses Flask and Authlib to demonstrate a simple Python app
that implements a SSO flow using OAuth2.0.

## Introduction
The app uses Azure AD OAuth2.0 for the IdP. 

## Prerequisites

You must have an Azure AD account with P1/P2 tiers to enable SSO.

Your application must be registered in Azure AD and configured to return 'SecurityGroup'
in the groupMembershipClaims in your application manifest. Read more details on this
here: https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/app-roles

## Installation

This example is written in Python 3

1. Clone the repo
2. Install pipenv
3. Install Flask and Authlib into your virtualenv
	pipenv install FLask
	pipenv install Authlib Flask



