(function(module) {
	"use strict";

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	var User = module.parent.require('./user'),
		Groups = module.parent.require('./groups'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),
		https = module.parent.require('https');

	var authenticationController = module.parent.require('./controllers/authentication');

	/**
	 * REMEMBER
	 *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
	 *   Save it into your config.json file instead:
	 *
	 *   {
	 *     ...
	 *     "oauth": {
	 *       "id": "someoauthid",
	 *       "secret": "youroauthsecret"
	 *     }
	 *     ...
	 *   }
	 *
	 *   ... or use environment variables instead:
	 *
	 *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
	 */

	var constants = Object.freeze({
			type: 'oauth2',	// Either 'oauth' or 'oauth2'
			name: 'eve',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth: {
				requestTokenURL: '',
				accessTokenURL: '',
				userAuthorizationURL: '',
				consumerKey: nconf.get('oauth:key'),	// don't change this line
				consumerSecret: nconf.get('oauth:secret'),	// don't change this line
			},
			oauth2: {
				authorizationURL: 'https://login.eveonline.com/oauth/authorize',
				tokenURL: 'https://login.eveonline.com/oauth/token',
				clientID: nconf.get('oauth:id'),	// don't change this line
				clientSecret: nconf.get('oauth:secret'),	// don't change this line
			},
			userRoute: 'https://login.eveonline.com/oauth/verify'	// This is the address to your app's "user profile" API endpoint (expects JSON)
		}),
		configOk = false,
		OAuth = {}, passportOAuth, opts;

	var groupmap = nconf.get('oauth:groups');

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
		winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
	} else if (!constants.userRoute) {
		winston.error('[sso-oauth] User Route required (library.js:31)');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];

			if (constants.type === 'oauth') {
				// OAuth options
				opts = constants.oauth;
				opts.callbackURL = nconf.get('url') + 'auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(token, secret, params, done) {
					this._oauth.get(constants.userRoute, token, secret, function(err, body, res) {
						if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;

								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			} else if (constants.type === 'oauth2') {
				// OAuth 2 options
				opts = constants.oauth2;
				opts.callbackURL = nconf.get('url') + 'auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
                                        this._oauth2._useAuthorizationHeaderForGET = true;
					this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
                                                
						if (err) { throw err; return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;

								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			}

			opts.passReqToCallback = true;

			passport.use(constants.name, new passportOAuth(opts, function(req, token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.displayName,
					email: profile.emails[0].value,
					isAdmin: profile.isAdmin,
					corpid: profile.corporation_id,
					allianceid: profile.alliance_id
				}, function(err, user) {
					if (err) {
						return done(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-check-square',
				scope: (constants.scope || '').split(',')
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(data, callback) {
		var profile = {};
		profile.id = data.CharacterID;
		profile.displayName = data.CharacterName;
		profile.emails = [{ value: data.CharacterName + "@localhost" }];

		https.get("https://esi.tech.ccp.is/v4/characters/"+data.CharacterID+"/", (res) => {
                        let data = '';
                        res.on('end', () => {
				var body = JSON.parse(data);
				profile.corporation_id = body.corporation_id;
				profile.alliance_id = body.alliance_id;
				callback(null, profile);
                        });
			res.on('data', (d) => {
                                data += d;
			});
		});
	}

	OAuth.login = function(payload, callback) {
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				// join them to any groups
				if (groupmap.hasOwnProperty(payload.corpid)) {
					Groups.join(groupmap[payload.corpid], uid, function(err) {});
				};
				if (groupmap.hasOwnProperty(payload.allianceid)) {
					Groups.join(groupmap[payload.allianceid], uid, function(err) {});
				};
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					// join them to any groups
					if (groupmap.hasOwnProperty(payload.corpid)) {
						Groups.join(groupmap[payload.corpid], uid, function(err) {});
					};
					if (groupmap.hasOwnProperty(payload.allianceid)) {
						Groups.join(groupmap[payload.allianceid], uid, function(err) {});
					};

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function(err) {
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

				User.getUidByEmail(payload.email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						User.create({
							username: payload.handle,
							email: payload.email
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function(oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	module.exports = OAuth;
}(module));
