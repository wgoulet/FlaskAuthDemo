# FlaskAuthDemo
This example app uses Flask and Authlib to demonstrate a simple Python app
that implements a SSO flow using OAuth2.0.

## Introduction
The app uses Azure AD OAuth2.0 for the IdP. In this example, I am using the OAuth2.0
flow to authenticate my user and authorize access based on their Azure AD Group membership.

The app parses the access_token returned from successful authentication to get user details.
The app also parses the id_token returned by the IdP to get user group information needed
to authorize the user and associate them with a role in the app.

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



