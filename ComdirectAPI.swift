//
//  ComdirectAPI.swift
//  MyMoney
//
//  Created by Schwarze on 25.01.22.
//

import Foundation

protocol ComdirectAPIDelegate {
    func didChangeState();
}

class ComdirectAPI {
    var logEnabled: Bool = false
    let urlBase = "https://api.comdirect.de"
    var delegate: ComdirectAPIDelegate?

    class REQ {
        static let mime_application_json = "application/json"
        static let mime_application_x_www_form_urlencoded = "application/x-www-form-urlencoded"
        static let hdr_x_once_authentication_info = "x-once-authentication-info"
        static let hdr_x_once_authentication = "x-once-authentication"
        static let hdr_x_http_request_info = "x-http-request-info"
        static let hdr_Accept = "Accept"
        static let hdr_ContentType = "Content-Type"
        static let hdr_Authorization = "Authorization"
    }

    enum TANProcedureType: String, CaseIterable {
        case M_TAN = "M_TAN"
        case P_TAN = "P_TAN"
        case P_TAN_PUSH = "P_TAN_PUSH"
        case P_TAN_APP = "P_TAN_APP"
    }

    enum ConnectionState {
        case disconnected
        case connected
        case error
    }

    enum ActiveState {
        case inactive
        case doing
        case done
        case failed

        func toString() -> String {
            switch self {
            case .inactive: return "inactive"
            case .doing: return "doing"
            case .done: return "done"
            case .failed: return "failed"
            }
        }
    }

    enum ProcessState {
        case none
        case getAuthToken
        case getSession
        case validateSessionTAN
        case userInteractionTAN
        case activateSessionTAN
        case getAuthTokenSecondary
        case refreshTokenSecondary
        case sessionTANReady
        case restOp

        func toString() -> String {
            switch self {
            case .none: return "none"
            case .getAuthToken: return "getAuthToken"
            case .getSession: return "getSession"
            case .validateSessionTAN: return "validateSessionTAN"
            case .userInteractionTAN: return "userInteractionTAN"
            case .activateSessionTAN: return "activateSessionTAN"
            case .refreshTokenSecondary: return "refreshTokenSecondary"
            case .getAuthTokenSecondary: return "getAuthTokenSecondary"
            case .sessionTANReady: return "sessionTANReady"
            case .restOp: return "restOp"
            }
        }
    }

    var connectionState : ConnectionState = .disconnected {
        didSet {
            delegate?.didChangeState()
        }
    }
    var processState: ProcessState = .none {
        didSet {
            delegate?.didChangeState()
        }
    }
    var activeState: ActiveState = .inactive {
        didSet {
            delegate?.didChangeState()
        }
    }

    var loginData = LoginData()
    var loginDataSecondary = LoginDataCDSecondary()
    var clientRequestID = ClientRequestID()
    var authRecord = AuthRecord()
    var authRecordSecondary = AuthRecord()
    var sessionObject = SessionObject()
    var tanChallenge = TANChallenge()
    var tanProcedureType: TANProcedureType? = nil
    var tanInputString: String?

    var accounts = AccountsRecord()
    var accountTransactionsForBanking = [AccountTransaction]()

    var session: URLSession

    init(session: URLSession) {
        self.session = session
    }

    func markBegin(state: ProcessState) {
        processState = state
        activeState = .doing
    }

    func markEnd(ok: Bool) {
        activeState = ok ? .done : .failed
    }

    // MARK: - Auth Token Handling

    func getAuthToken(completion: @escaping (CDError?) -> ()) {
        guard connectionState != .connected, activeState != .doing, loginData.isValid() else {
            completion(CDError.badState())
            return
        }

        markBegin(state: .getAuthToken)

        guard let url = URL(string: urlBase + "/oauth/token") else {
            completion(CDError.internalErrorURL())
            return
        }
        guard var request = reqAuth(method: "POST", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }

        let parameters: [String: String] = [
            "client_id": loginData.clientID,
            "client_secret": loginData.clientSecret,
            "grant_type": "password",
            "username": loginData.userName,
            "password": loginData.password
        ]
        request.httpBody = Self.percentEncode(dict: parameters)
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            let e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            self.authRecord.parse(data: data)

            self.connectionState = self.authRecord.isUsable() && e == nil ? .connected : .disconnected

            self.markEnd(ok: e == nil && self.authRecord.isUsable())
            completion(e)
        }
        task.resume()
    }

    func getAuthTokenSecondary(completion: @escaping (CDError?) -> ()) {
        guard connectionState == .connected, activeState != .doing,
              processState == .activateSessionTAN, activeState == .done,
            authRecord.isUsable() else {
            completion(CDError.badState())
            return
        }

        markBegin(state: .getAuthTokenSecondary)
        guard let url = URL(string: urlBase + "/oauth/token") else {
            completion(CDError.internalErrorURL())
            return
        }
        guard var request = reqAuth(method: "POST", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }

        loginDataSecondary.clientID = loginData.clientID
        loginDataSecondary.clientSecret = loginData.clientSecret
        loginDataSecondary.token = authRecord.access_token

        let parameters: [String: String] = [
            "client_id": loginDataSecondary.clientID,
            "client_secret": loginDataSecondary.clientSecret,
            "grant_type": "cd_secondary",
            "token": loginDataSecondary.token
        ]
        request.httpBody = Self.percentEncode(dict: parameters)
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            let e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            self.authRecordSecondary.parse(data: data)

            self.markEnd(ok: e == nil && self.authRecordSecondary.isUsable())
            completion(e)
        }
        task.resume()
    }

    func refreshToken(completion: @escaping (CDError?) -> ()) {
        guard connectionState == .connected, activeState != .doing else {
            completion(CDError.badState())
            return
        }

        let lastProcessState = processState
        let lastActiveState = activeState

        markBegin(state: .refreshTokenSecondary)
        guard let url = URL(string: urlBase + "/oauth/token") else {
            completion(CDError.internalErrorURL())
            return
        }
        guard var request = reqAuth(method: "POST", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }

        let parameters: [String: String] = [
            "client_id": loginData.clientID,
            "client_secret": loginData.clientSecret,
            "grant_type": "refresh_token",
            "refresh_token": authRecordSecondary.refresh_token
        ]
        request.httpBody = Self.percentEncode(dict: parameters)

        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            let e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            self.authRecordSecondary.parse(data: data)

            self.markEnd(ok: e == nil && self.authRecordSecondary.isUsable())
            completion(e)
            self.processState = lastProcessState
            self.activeState = lastActiveState
        }
        task.resume()
    }

    // MARK: - Session Handling

    func getSession(completion: @escaping (CDError?) -> ()) {
        guard processState == .getAuthToken, activeState == .done else {
            completion(CDError.badState())
            return
        }
        markBegin(state: .getSession)
        guard let url = URL(string: urlBase + "/api/session/clients/user/v1/sessions") else {
            completion(CDError.internalErrorURL())
            return
        }
        guard let request = reqSsn(method: "GET", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            var e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            if e == nil {
                do {
                    try self.sessionObject.parse(data: data)
                } catch let e2 {
                    e = CDError(msg: "", nested: e2)
                }
            }
            self.markEnd(ok: e == nil && self.sessionObject.hasIdentifier())
            completion(e)
        }
        task.resume()
    }

    // MARK: - TAN / Session TAN Handling

    /**
     ATTENTION:
     THE COMDIRECTAPI SPECIFICATION STATES, THAT
     REQUESTING 5 TAN CHALLENGES
     WITHOUT CONSUMING ONE
     LEADS TO LOCKING THE ONLINE ACCOUNT ACCESS.

     see section 2.3 in that specification.
     */
    func validateSessionTAN(preferredTanProcedureType: TANProcedureType? = nil, completion: @escaping (CDError?) -> ()) {
        guard processState == .getSession, activeState == .done,
              sessionObject.hasIdentifier() else {
            completion(CDError.badState())
            return
        }
        markBegin(state: .validateSessionTAN)
        guard let url = URL(string: urlBase + "/api/session/clients/user/v1/sessions/\(sessionObject.identifier)/validate") else {
            completion(CDError.internalErrorURL())
            return
        }
        guard var request = reqSsn(method: "POST", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }
        if let tanType = preferredTanProcedureType {
            let onceAuthInfo = ["typ": tanType.rawValue]
            guard let onceAuthInfoData = try? JSONSerialization.data(withJSONObject: onceAuthInfo, options: .fragmentsAllowed) else {
                completion(CDError(msg: "error creating onceAuthInfo"))
                return
            }
            guard let onceAuthInfoStr = String(data: onceAuthInfoData, encoding: .utf8) else {
                completion(CDError(msg: "error creating onceAuthInfo"))
                return
            }
            request.addValue(onceAuthInfoStr, forHTTPHeaderField: REQ.hdr_x_once_authentication_info)
        }
        request.httpBody = sessionObject.jsonData()
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            var e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)

            if e == nil {
                do {
                    _ = try self.tanChallenge.parse(response: response)
                } catch let error {
                    e = CDError(msg: "", nested: error)
                }
            }
            self.markEnd(ok: e == nil)
            completion(e)
        }
        task.resume()
    }

    func markUserInteraction(activeState: ActiveState, tanString: String?) {
        guard
            (processState == .validateSessionTAN && self.activeState == .done) ||
                (processState == .userInteractionTAN && self.activeState == .doing) else {
                    return
                }
        self.tanInputString = tanString
        self.processState = .userInteractionTAN
        self.activeState = activeState
    }

    /**
     ATTENTION:
     AFTER THREE WRONG TAN ACTIVATIONS, ACCESS TO THE ONLINE BANKING ACCOUNT
     WILL BE BLOCKED. THE ERROR COUNT CAN BE RESET WHEN LOGGING IN
     ON THE COMDIRECT WEBSITE.

     see section 2.4 in the Comdirect API specification.
     */
    func activateSessionTAN(completion: @escaping (CDError?) -> ()) {
        guard processState == .userInteractionTAN, activeState == .done else {
            completion(CDError.badState())
            return
        }
        processState = .activateSessionTAN
        activeState = .doing
        guard let url = URL(string: urlBase + "/api/session/clients/user/v1/sessions/\(sessionObject.identifier)") else {
            completion(CDError.internalErrorURL())
            return
        }

        guard var request = reqSsn(method: "PATCH", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }
        guard let once_auth_info = tanChallenge.onceAuthenticationInfoString() else {
            completion(CDError.init(msg: "Error building TAN challenge info for activation"))
            return
        }
        request.addValue(once_auth_info, forHTTPHeaderField: REQ.hdr_x_once_authentication_info)
        if tanChallenge.typ != TANProcedureType.P_TAN_PUSH.rawValue {
            guard let tanString = tanInputString else {
                completion(CDError(msg: "TAN type is not P_TAN_PUSH and no TAN has been provided"))
                return
            }
            request.addValue(tanString, forHTTPHeaderField: REQ.hdr_x_once_authentication)
        }
        request.httpBody = sessionObject.jsonData()
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            var e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            if e == nil {
                do {
                    try self.sessionObject.parse(data: data)
                } catch let e2 {
                    e = CDError(msg: "Error: Session TAN was activated, but response could not be parsed - this should not count towards the validateTAN limit", nested: e2)
                }
            }
            self.activeState = e != nil ? .failed : .done
            completion(e)
        }
        task.resume()
    }

    // MARK: - Account Queries

    func getAccountBalances(completion: @escaping (CDError?) -> ()) {
        guard let url = URL(string: urlBase + "/api/banking/clients/user/v2/accounts/balances") else {
            completion(CDError.internalErrorURL())
            return
        }

        guard let request = reqRest(method: "GET", url: url) else {
            completion(CDError.internalErrorREQ())
            return
        }
        logReq(req: request)
        let task = session.dataTask(with: request) { data, response, error in
            let e = CDError.check2XX(resp: response, error: error)
            self.logResp(data: data, response: response, error: error)
            _ = self.accounts.parse(data: data)
            completion(e)
        }
        task.resume()
    }

    // - paging-first und paging-count
    func getAccountTransactions(index: Int? = nil, count: Int? = nil, completion: @escaping (CDError?) -> ()) {
        let urlStr = urlBase + "/api/banking/v1/accounts/${accountId}/transactions"

        let accountIds = accounts.accounts.map { $0.accountId }
        var results: [String: Any] = [:]

        for accountId in accountIds {
            let str = urlStr.replacingOccurrences(of: "${accountId}", with: accountId)
            guard let url = URL(string: str),
                  var urlcomps = URLComponents(url: url, resolvingAgainstBaseURL: false)
            else {
                completion(CDError.internalErrorURL())
                return
            }
            urlcomps.queryItems = [
                URLQueryItem(name: "paging-count", value: "100")
            ]
            guard let url : URL = urlcomps.url else {
                completion(CDError.internalErrorURL())
                return
            }

            guard let request = reqRest(method: "GET", url: url) else {
                completion(CDError.internalErrorREQ())
                return
            }
            logReq(req: request)
            let task = session.dataTask(with: request) { data, response, error in
                let e = CDError.check2XX(resp: response, error: error)
                self.logResp(data: data, response: response, error: error)
                if let data = data {
                    if let transactions = AccountTransaction.parseTransactions(data: data) {
                        self.accountTransactionsForBanking.append(contentsOf: transactions)
                    }
                }
                results[accountId] = data ?? Data()
                // FIXME: error is ignored, when completion is not called here
                if (results.count == accountIds.count) {
                    completion(e)
                }
            }
            task.resume()
        }
    }

    // MARK: - Request Helper Methods

    func reqAuth(method: String, url: URL) -> URLRequest? {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue(REQ.mime_application_json, forHTTPHeaderField: REQ.hdr_Accept)
        request.addValue(REQ.mime_application_x_www_form_urlencoded, forHTTPHeaderField: REQ.hdr_ContentType)
        return request
    }

    func reqSsn(method: String, url: URL) -> URLRequest? {
        clientRequestID.prepareNext()
        guard let http_request_info = clientRequestID.jsonString() else {
            return nil
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.addValue(REQ.mime_application_json, forHTTPHeaderField: REQ.hdr_Accept)
        request.addValue(REQ.mime_application_json, forHTTPHeaderField: REQ.hdr_ContentType)
        request.addValue("Bearer " + authRecord.access_token, forHTTPHeaderField: REQ.hdr_Authorization)
        request.addValue(http_request_info, forHTTPHeaderField:REQ.hdr_x_http_request_info)
        return request
    }

    func reqRest(method: String, url: URL) -> URLRequest? {
        clientRequestID.prepareNext()
        guard let http_request_info = clientRequestID.jsonString() else {
            return nil
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.addValue(REQ.mime_application_json, forHTTPHeaderField: REQ.hdr_Accept)
        request.addValue(REQ.mime_application_json, forHTTPHeaderField: REQ.hdr_ContentType)
        request.addValue("Bearer " + authRecordSecondary.access_token, forHTTPHeaderField: REQ.hdr_Authorization)
        request.addValue(http_request_info, forHTTPHeaderField:REQ.hdr_x_http_request_info)
        return request
    }

    // MARK: - Log Helpers

    func logReq(req: URLRequest) {
        guard logEnabled else { return }
        print(
            "req:\n" +
            "  url=\(String(describing: req.url))\n" +
            "  hdr=\(String(describing: req.allHTTPHeaderFields))\n" +
            "  bod=\(String(describing: String(data: req.httpBody ?? Data(), encoding: .utf8)))\n"
        )
    }

    func logResp(data: Data?, response: URLResponse?, error: Error?) {
        guard logEnabled || error != nil else { return }
        var msg = "resp:\n"
        if let e = error {
            msg += "  error=" + e.localizedDescription + "\n"
        } else {
            msg += "  error=none (ok)\n"
        }
        if let d = data, let s = String(data: d, encoding: .utf8) {
            msg += "  data=" + s + "\n"
        } else {
            msg += "  data=(none)\n"
        }
        if let r = response {
            msg += "  response=" + String(describing: r) + "\n"
        } else {
            msg += "  response=(none)\n"
        }
        print(msg)
    }

    // MARK: - Form Encoding Helpers

    static let urlQueryValueAllowed: CharacterSet = {
        let general = ":#[]@"
        let sub = "!$&'()*+,;="
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: general + sub)
        return allowed
    }()

    static func percentEncode(dict: [String: String]) -> Data? {
        let kvArray = dict.map { key, value -> String in
            let ek = key.addingPercentEncoding(withAllowedCharacters: Self.urlQueryValueAllowed) ?? ""
            let ev = value.addingPercentEncoding(withAllowedCharacters: Self.urlQueryValueAllowed) ?? ""
            return ek + "=" + ev
        }
        let str = kvArray.joined(separator: "&")
        let data = str.data(using: .utf8)
        return data
    }

    static func percentDecode(string: String) -> [String: String] {
        let array = string.split(separator: "&")
        let array2: [[Substring]] = array.map { $0.split(separator: "=") }
        let dict: [String: String] = array2.reduce(into: [:]) {
            $0[String($1.first ?? "")] = String($1.last ?? "")
        }
        return dict
    }

    // MARK: - Helper Model Classes

    class LoginData {
        let userName: String
        let password: String
        let clientSecret: String
        let clientID: String

        init() {
            userName = ""
            password = ""
            clientSecret = ""
            clientID = ""
        }

        init(userName: String, password: String, clientSecret: String, clientID: String) {
            self.userName = userName
            self.password = password
            self.clientSecret = clientSecret
            self.clientID = clientID
        }

        func isValid() -> Bool {
            return !(userName.isEmpty || password.isEmpty || clientSecret.isEmpty || clientID.isEmpty)
        }
    }


    class LoginDataCDSecondary {
        var clientSecret = ""
        var clientID = ""
        var token = ""
    }


    class ClientRequestID {
        var sessionID = String() // randomly calculated
        var requestID = String() // 9-digit number - for instance the current time
        let df : DateFormatter = {
            let df = DateFormatter()
            df.dateFormat = "HHmmssSSS"
            return df
        }()

        func prepareNext() {
            if sessionID.isEmpty {
                calculateSessionID()
            }
            calculateRequestId()
        }

        func jsonString() -> String? {
            let dict = [
                "clientRequestId": [
                    "sessionId": sessionID,
                    "requestId": requestID
                ]
            ]
            guard let data = try? JSONSerialization.data(withJSONObject: dict, options: .fragmentsAllowed) else {
                return nil
            }
            let jsonStr = String(decoding: data, as: UTF8.self)
            return jsonStr
        }

        func calculateSessionID() {
            let uuid = UUID()
            let uuidString = uuid.uuidString.replacingOccurrences(of: "-", with: "")
            let uuidSubString = uuidString.prefix(32)
            sessionID = String(uuidSubString)
        }

        func calculateRequestId() {
            let date = Date()
            requestID = df.string(from: date)
        }
    }


    class AuthRecord {
        var access_token = ""
        var token_type = ""
        var refresh_token = ""
        var expires_in = 0
        var scope = ""
        var kdnr = ""
        var bpid = ""
        var kontaktId = ""

        func isUsable() -> Bool {
            if access_token.isEmpty {
                return false
            }
            return true
        }

        func parse(data: Data?) {
            guard let data = data else {
                return
            }
            guard let objectData = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) else {
                return
            }
            guard let objectDict = objectData as? [String: Any] else {
                return
            }
            access_token = objectDict["access_token"] as? String ?? ""
            token_type = objectDict["token_type"] as? String ?? ""
            refresh_token = objectDict["refresh_token"] as? String ?? ""
            expires_in = objectDict["expires_in"] as? Int ?? 0
            scope = objectDict["scope"] as? String ?? ""
            kdnr = objectDict["kdnr"] as? String ?? ""
            bpid = objectDict["bpid"] as? String ?? ""
            kontaktId = objectDict["kontaktId"] as? String ?? ""
        }
    }


    class SessionObject {
        var identifier: String = "" // max len 40
        var sessionTanActive: Bool = false
        var activated2FA: Bool = false

        func parse(data: Data?) throws {
            guard let data = data else { throw CDError(msg: "Session object has no data") }
            let obj = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
            var dict: [String: Any] = [:]
            if let ary = obj as? [Any] {
                guard let d = ary.first as? [String: Any] else { throw CDError(msg: "Session object array has no dictionary") }
                dict = d
            } else if let d = obj as? [String: Any] {
                dict = d
            } else { throw CDError(msg: "Session object is neither array nor dictionary") }
            identifier = dict["identifier"] as? String ?? ""
            sessionTanActive = dict["sessionTanActive"] as? Bool ?? false
            activated2FA = dict["activated2FA"] as? Bool ?? false
        }

        func jsonData() -> Data? {
            let parameters: [String: Any] = [
                "identifier": identifier,
                "sessionTanActive": true,
                "activated2FA": true
            ]
            return try? JSONSerialization.data(withJSONObject: parameters, options: .fragmentsAllowed)
        }

        func hasIdentifier() -> Bool {
            return !identifier.isEmpty
        }
    }


    class TANChallenge {
        var id: String = ""
        var typ: String = ""
        var challenge: String = ""
        var availableTypes: [String] = []

        func parse(response: URLResponse?) throws {
            guard let resp = response as? HTTPURLResponse else { throw CDError(msg: "Not an HTTPResponse") }
            guard let str = resp.value(forHTTPHeaderField: REQ.hdr_x_once_authentication_info) else { throw CDError(msg: "Missing header field " + REQ.hdr_x_once_authentication_info) }
            guard let data = str.data(using: .utf8) else { throw CDError(msg: "Error decoding as UTF8") }
            let obj = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed)
            guard let dict = obj as? [String: Any] else { throw CDError(msg: "JSON not a dictionary") }
            guard let _id = dict["id"] as? String else { throw CDError(msg: "Error extracting id") }
            id = _id
            guard let _typ = dict["typ"] as? String else { throw CDError(msg: "Error extracting typ") }
            typ = _typ
            challenge = dict["challenge"] as? String ?? "" // challenge is optional
            availableTypes = dict["availableTypes"] as? [String] ?? [] // assume optional for now
        }

        func onceAuthenticationInfoString() -> String? {
            let onceAuthInfoObj = ["id": id]
            guard let onceAuthInfoData = try? JSONSerialization.data(withJSONObject: onceAuthInfoObj, options: .fragmentsAllowed) else { return nil }
            guard let onceAuthInfo = String(data: onceAuthInfoData, encoding: .utf8) else { return nil }
            return onceAuthInfo
        }

        func photoTANImage() -> UIImage? {
            // TODO: Check P_TAN_APP - what happens there?
            guard typ == "P_TAN" else {
                print("tan challenge type is \(typ) - no image")
                return nil
            }
            guard let chd = Data(base64Encoded: challenge, options: .ignoreUnknownCharacters) else {
                print("tan challenge could not be base64 decoded")
                return nil
            }
            guard let img = UIImage(data: chd) else {
                print("could not create uiimage from tan challenge")
                return nil
            }
            return img
        }

        func debugInfoString() -> String {
            var s = ""
            s += "id:\(id) typ:\(typ) challenge:\(challenge) availabledTypes:\(availableTypes)"
            return s
        }
    }


    class AccountsRecord {
        var accounts: [AccountRecord] = []

        func parse(data: Data?) -> Bool {
            guard let data = data else { return false }
            guard let obj = try? JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) else { return false }
            guard let dict = obj as? [String: Any] else { return false }
            guard let values = dict["values"] as? [Any] else { return false }
            for value in values {
                let account = AccountRecord()
                guard account.parse(obj: value) == true else { return false }
                accounts.append(account)
            }
            return true
        }
    }


    class AccountRecord {
        var accountId: String = ""
        var accountDisplayId: String = ""
        var currency: String = ""
        var accountTypeKey: String = ""
        var accountTypeText: String = ""

        func parse(obj: Any?) -> Bool {
            guard let obj = obj else { return false }
            guard let dict1 = obj as? [String: Any] else { return false }
            guard let dict = dict1["account"] as? [String: Any] else { return false }
            accountId = dict["accountId"] as? String ?? ""
            accountDisplayId = dict["accountDisplayId"] as? String ?? ""
            currency = dict["currency"] as? String ?? ""
            guard let accountType = dict["accountType"] as? [String: Any] else { return false }
            accountTypeKey = accountType["key"] as? String ?? ""
            accountTypeText = accountType["text"] as? String ?? ""
            return true
        }
    }


    class AccountTransaction {
        var reference: String = "" // unique reference key
        var bookingDate: String = ""
        var amountValue: String = ""
        var amountUnit: String = ""
        var holderName: String = ""
        var valutaDate: String = ""
        var remittanceInfo: String = "" // text
        var transactionTypeKey: String = ""
        var transactionTypeText: String = ""

        func parse(obj: Any?) -> Bool {
            guard let dict = obj as? [String: Any] else { return false }
            reference = dict["reference"] as? String ?? ""
            bookingDate = dict["bookingDate"] as? String ?? ""
            guard let amountDict = dict["amount"] as? [String: Any] else { return false }
            amountValue = amountDict["value"] as? String ?? ""
            amountUnit = amountDict["unit"] as? String ?? ""

            let names = ["deptor", "creditor", "remitter"]
            for name in names {
                if let holderDict = dict[name] as? [String: Any] {
                    holderName = holderDict["holderName"] as? String ?? ""
                }
            }

            remittanceInfo = dict["remittanceInfo"] as? String ?? ""
            if let transactionTypeDict = dict["transactionType"] as? [String: Any] {
                transactionTypeKey = transactionTypeDict["key"] as? String ?? ""
                transactionTypeText = transactionTypeDict["text"] as? String ?? ""
            }
            return true
        }

        static func parseTransactions(data: Data?) -> [AccountTransaction]? {
            guard let data = data else { return nil }
            guard let obj = try? JSONSerialization.jsonObject(with: data, options: .allowFragments) else { return nil }
            guard let dict = obj as? [String: Any] else { return nil }
            guard let values = dict["values"] as? [Any] else { return nil }
            var result = [AccountTransaction]()
            for value in values {
                guard let transactionDict = value as? [String: Any] else { continue }
                let accountTransaction = AccountTransaction()
                if !accountTransaction.parse(obj: transactionDict) { continue }
                result.append(accountTransaction)
            }
            return result
        }
    }


    class CDError : Error, LocalizedError {
        let msg: String
        let http: Int
        let nested: Error?
        init(http: Int, nested: Error?) {
            self.msg = "Unexpected HTTP Status"
            self.http = http
            self.nested = nested
        }
        init(msg: String, nested: Error? = nil) {
            self.msg = msg
            self.http = 0
            self.nested = nested
        }
        var errorDescription: String? {
            let h = http != 0 ? " HTTPStatusCode=\(http)" : ""
            let e = nested != nil ? " Nested Error=" + String(describing: nested) : ""
            return "\(msg)\(h)\(e)"
        }
        static func badState() -> CDError {
            return CDError(msg: "Invalid state for function call")
        }
        static func internalError(msg: String) -> CDError {
            return CDError(msg: msg)
        }
        static func internalErrorREQ() -> CDError {
            return CDError(msg: "Error building request - likely because of incorrect client request id")
        }
        static func internalErrorURL() -> CDError {
            return CDError(msg: "Error building URL")
        }
        static func check2XX(resp: URLResponse?, error: Error?) -> CDError? {
            var res : CDError? = nil
            if let e = error {
                res = CDError(msg: "", nested: e)
            }
            if let r = resp as? HTTPURLResponse, !(200..<300 ~= r.statusCode) {
                res = CDError(http: r.statusCode, nested: res)
            }
            return res
        }
    }
}
