import { Heading, Container, Badge } from '@chakra-ui/react'
import React from 'react'
import { Layout } from '../components/Layout'
import Contact from './Payment'
import ContactForm from './Payment2'

export default function ProtectedPage() {
  return (
    <Layout>
      
        <ContactForm />
      {/* <Container maxW='container.lg' overflowX='auto' py={4}>
        {/* <Contact /> */}
      {/* </Container>  */}
    </Layout>
  )
}
