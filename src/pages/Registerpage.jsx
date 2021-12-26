import {
  Button,
  Center,
  chakra,
  FormControl,
  FormLabel,
  Heading,
  Input,
  Stack,
  HStack,
  useToast,
  Flex,
  Box,
  Image,
  Link,
  Checkbox,
} from "@chakra-ui/react";
import React, { useEffect, useRef, useState } from "react";
import { FaGoogle } from "react-icons/fa";
import { useHistory } from "react-router-dom";
import { Card } from "../components/Card";
import DividerWithText from "../components/DividerWithText";
import { Layout } from "../components/Layout";
import { useAuth } from "../contexts/AuthContext";
import useMounted from "../hooks/useMounted";
import { useMediaQuery } from "@chakra-ui/media-query";
import { auth, app } from '../utils/init-firebase'
import { getDatabase, ref, set } from "firebase/database";


export default function Registerpage() {
  const history = useHistory();
  const [username, setUserName] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmiting, setisSubmiting] = useState(false);
  const toast = useToast();

  const { register, signInwithGoogle } = useAuth();
  const [isNotSmallerScreen] = useMediaQuery("(min-width:600px)");

  const mounted = useMounted();

  return (
    <Layout>
      <Heading textAlign="center" my={12}>
        Register
      </Heading>
      <Card maxW="md" mx="auto" mt={4}>
        <chakra.form
          onSubmit={async (e) => {
            e.preventDefault();
            // your register logic here
            // console.log(email, password)
            if (!email || !password || !name) {
              toast({
                description: "credentials not valid",
                status: "error",
                duration: 5000,
                isClosable: true,
              });
              console.log(e);
            }
            setisSubmiting(true);
            register(email, password, name)
              .then((response) => {
                // app.database.ref("currentUsers/details/" + "/" + name).set({
                //   currentUser: name,
                //   currentUserEmail: email,
                //   currentUserPassword: password,
                // }) 
                const db = getDatabase();
                set(ref(db,'currentUser/details/' + username), {
                  userName: username,
                  currentUser: name,
                  currentUserEmail: email,
                  currentUserPassword: password,
                });
                history.push("/profile");
                console.log(response);
              })
              .catch((error) => {
                console.log(error.message);

                toast({
                  description: error.message,
                  status: "error",
                  duration: 5000,
                  isClosable: true,
                });
              })
              .finally(() => mounted.current && setisSubmiting(false));
          }}
        >
          <Stack spacing="6">
          <FormControl id="username" isRequired>
              <FormLabel>Username</FormLabel>
              <Input type="text" 
              value = {username}
              onChange={(e) => setUserName(e.target.value)}
              name = "name"
              autoComplete="name"
              />
            </FormControl>
            <FormControl id="firstName" isRequired>
              <FormLabel>Name</FormLabel>
              <Input type="text" 
              value = {name}
              onChange={(e) => setName(e.target.value)}
              name = "name"
              autoComplete="name"
              />
            </FormControl>
            <FormControl id="email" isRequired>
              <FormLabel>Email address</FormLabel>
              <Input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                name="email"
                type="email"
                autoComplete="email"
                required
              />
            </FormControl>
            <FormControl id="password">
              <FormLabel>Password</FormLabel>
              <Input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                name="password"
                type="password"
                autoComplete="password"
                required
              />
            </FormControl>
            <Button
              isLoading={isSubmiting}
              type="submit"
              colorScheme="primary"
              size="lg"
              fontSize="md"
            >
              Sign up
            </Button>
          </Stack>
        </chakra.form>
        <Center my={4}>
          <Button variant="link" onClick={() => history.push("/login")}>
            Login
          </Button>
        </Center>
        <DividerWithText my={6}>OR</DividerWithText>
        <Button
          variant="outline"
          isFullWidth
          colorScheme="red"
          leftIcon={<FaGoogle />}
          onClick={() =>
            signInwithGoogle()
              .then((user) => console.log(user))
              .catch((error) => console.log(error))
          }
        >
          Sign in with Google
        </Button>
      </Card>
      <Stack minH={"100vh"} direction={{ base: "column", md: "row" }}>
        <Flex p={8} flex={1} align={"center"} justify={"center"}>
          <Stack spacing={4} w={"full"} maxW={"md"}>
            <Heading fontSize={"2xl"}>Register your account</Heading>
            <FormControl id="firstName" >
              <FormLabel>Name</FormLabel>
              <Input type="name" />
            </FormControl>
            <FormControl id="email">
              <FormLabel>Email address</FormLabel>
              <Input type="email" />
            </FormControl>
            <FormControl id="password">
              <FormLabel>Password</FormLabel>
              <Input type="password" />
            </FormControl>
            <Stack spacing={6}>
              <Stack
                direction={{ base: "column", sm: "row" }}
                align={"start"}
                justify={"space-between"}
              >
                <Checkbox>Remember me</Checkbox>
                <Link color={"blue.500"}>Forgot password?</Link>
              </Stack>
              <Button colorScheme={"blue"} variant={"solid"}>
                Sign in
              </Button>
            </Stack>
          </Stack>
        </Flex>
        <Flex flex={1}>
          <Image
            alignSelf="center"
            mt={isNotSmallerScreen ? "0" : "12"}
            mb={isNotSmallerScreen ? "0" : "12"}
            borderRadius="full"
            backgroundColor="transparent"
            boxShadow="lg"
            boxSize="400px"
            alt={"Login Image"}
            objectFit={"cover"}
            src={
              "https://images.unsplash.com/photo-1486312338219-ce68d2c6f44d?ixid=MXwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHw%3D&ixlib=rb-1.2.1&auto=format&fit=crop&w=1352&q=80"
            }
          />
        </Flex>
      </Stack>
    </Layout>
  );
}
