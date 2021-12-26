import { createContext, useContext, useEffect, useState } from "react";
import { auth } from '../utils/init-firebase'
import { 
    createUserWithEmailAndPassword,
    signInWithPopup,
    signInWithEmailAndPassword,
    onAuthStateChanged,
    signOut,
    GoogleAuthProvider,
    sendPasswordResetEmail, 
    confirmPasswordReset } from "@firebase/auth";

const AuthContext = createContext({
    currentUser: null,
    register: () => Promise,
    login: () => Promise,
    logout: () => Promise,
    signInwithGoogle: () => Promise,
    forgotPassword: () => Promise,
    resetPassword: () => Promise,

})

export const useAuth = () => useContext(AuthContext)

export default function AuthContextProvider({ children }) {
    const [currentUser, setcurrentUser] = useState(null)

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, user => {
            setcurrentUser(user)
            
        })
        return () => {
            unsubscribe()
        }
    }, [])

    function register(email, password) {
        return createUserWithEmailAndPassword(auth, email, password)
    }

    function login(email, password) {
        return signInWithEmailAndPassword(auth, email, password)
    }

    function signInwithGoogle() {
        const provider = new GoogleAuthProvider();
        return signInWithPopup(auth, provider)
    }

    function forgotPassword(email) {
        return sendPasswordResetEmail(auth, email, {
            url: "http://localhost:3000/login",
        })
    }
    function resetPassword(oobCode, newPassword) {
        return confirmPasswordReset(auth, oobCode, newPassword)
    }

    function logout() {
        return signOut(auth)
    }
    const value = {
        currentUser,
        register,
        login,
        logout,
        signInwithGoogle,
        forgotPassword,
        resetPassword
    }
    
    return <AuthContext.Provider value={value}>
        {children}
    </AuthContext.Provider>
}