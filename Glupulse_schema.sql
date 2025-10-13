--
-- PostgreSQL database dump
--

-- Dumped from database version 18.0 (Debian 18.0-1.pgdg13+3)
-- Dumped by pg_dump version 18.0 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: activity_activity_intensity; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.activity_activity_intensity AS ENUM (
    'Low',
    'Medium',
    'High'
);


ALTER TYPE public.activity_activity_intensity OWNER TO postgres;

--
-- Name: chat_conversations_participant1_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_conversations_participant1_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_conversations_participant1_type OWNER TO postgres;

--
-- Name: chat_conversations_participant2_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_conversations_participant2_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_conversations_participant2_type OWNER TO postgres;

--
-- Name: chat_messages_sender_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_messages_sender_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_messages_sender_type OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.doctor_appointments_appointment_status AS ENUM (
    'scheduled',
    'confirmed',
    'completed',
    'cancelled',
    'rescheduled',
    'no_show'
);


ALTER TYPE public.doctor_appointments_appointment_status OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.doctor_appointments_appointment_type AS ENUM (
    'video_call',
    'chat',
    'in_person',
    'phone_call'
);


ALTER TYPE public.doctor_appointments_appointment_type OWNER TO postgres;

--
-- Name: seller_promotions_promotion_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.seller_promotions_promotion_type AS ENUM (
    'percentage',
    'fixed_amount'
);


ALTER TYPE public.seller_promotions_promotion_type OWNER TO postgres;

--
-- Name: seller_seller_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.seller_seller_status AS ENUM (
    'active',
    'inactive',
    'suspended'
);


ALTER TYPE public.seller_seller_status OWNER TO postgres;

--
-- Name: user_cart_cart_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_cart_cart_status AS ENUM (
    'active',
    'purchased',
    'deleted',
    ''
);


ALTER TYPE public.user_cart_cart_status OWNER TO postgres;

--
-- Name: user_order_order_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_order_order_status AS ENUM (
    'Processing',
    'Shipped',
    'Delivered',
    'Rejected',
    'Cancelled'
);


ALTER TYPE public.user_order_order_status OWNER TO postgres;

--
-- Name: user_order_payment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_order_payment_status AS ENUM (
    'Pending',
    'Paid',
    'Failed'
);


ALTER TYPE public.user_order_payment_status OWNER TO postgres;

--
-- Name: user_transaction_payment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_transaction_payment_status AS ENUM (
    'Pending',
    'Success',
    'Failed',
    'Expired'
);


ALTER TYPE public.user_transaction_payment_status OWNER TO postgres;

--
-- Name: user_vip_vip_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_vip_vip_status AS ENUM (
    'Pending',
    'Active',
    'Expired'
);


ALTER TYPE public.user_vip_vip_status OWNER TO postgres;

--
-- Name: users_user_gender; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.users_user_gender AS ENUM (
    'Male',
    'Female'
);


ALTER TYPE public.users_user_gender OWNER TO postgres;

--
-- Name: on_update_current_timestamp_chat_conversations(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_chat_conversations() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.last_message_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_chat_conversations() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_delivery_orders(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_delivery_orders() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_delivery_orders() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_doctor_appointments(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_doctor_appointments() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_doctor_appointments() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_doctor_consultation_records(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_doctor_consultation_records() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_doctor_consultation_records() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_glucose_manual(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_glucose_manual() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.glucose_inputdate = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_glucose_manual() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_seller_promotions(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_seller_promotions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_seller_promotions() OWNER TO postgres;

--
-- Name: update_address_updated_at(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_address_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_address_updated_at() OWNER TO postgres;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.user_updated_at_auth = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activity; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity (
    activity_id character varying(10) NOT NULL,
    activity_categoryid character varying(10) DEFAULT NULL::character varying,
    activity_name character varying(50) NOT NULL,
    activity_duration integer,
    activity_caloriesperminute double precision,
    activity_intensity public.activity_activity_intensity,
    activity_information character varying(255) DEFAULT NULL::character varying,
    activity_picturepath character varying(255) DEFAULT NULL::character varying
);


ALTER TABLE public.activity OWNER TO postgres;

--
-- Name: activity_categories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_categories (
    activity_categoryid character varying(10) NOT NULL,
    activity_category character varying(30) DEFAULT NULL::character varying,
    activity_categorydescription text
);


ALTER TABLE public.activity_categories OWNER TO postgres;

--
-- Name: activity_recommendation_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_recommendation_items (
    item_id character varying(30) NOT NULL,
    recommendation_id character varying(30) NOT NULL,
    activity_id character varying(10) DEFAULT NULL::character varying,
    timestamp_date timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.activity_recommendation_items OWNER TO postgres;

--
-- Name: activity_recommendations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_recommendations (
    recommendation_id character varying(30) NOT NULL,
    user_id character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.activity_recommendations OWNER TO postgres;

--
-- Name: chat_conversations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.chat_conversations (
    conversation_id character varying(60) NOT NULL,
    participant1_id character varying(20) NOT NULL,
    participant1_type public.chat_conversations_participant1_type NOT NULL,
    participant2_id character varying(20) NOT NULL,
    participant2_type public.chat_conversations_participant2_type NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_message_at timestamp with time zone
);


ALTER TABLE public.chat_conversations OWNER TO postgres;

--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.chat_messages (
    message_id character varying(70) NOT NULL,
    conversation_id character varying(60) NOT NULL,
    sender_id bigint NOT NULL,
    sender_type public.chat_messages_sender_type NOT NULL,
    message_content text NOT NULL,
    sent_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_read boolean DEFAULT false
);


ALTER TABLE public.chat_messages OWNER TO postgres;

--
-- Name: counter_activity_recommendationitem; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_activity_recommendationitem (
    counter_date date NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_activity_recommendationitem OWNER TO postgres;

--
-- Name: counter_activityid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_activityid (
    counter bigint NOT NULL
);


ALTER TABLE public.counter_activityid OWNER TO postgres;

--
-- Name: counter_cartid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_cartid (
    user_id character varying(20) NOT NULL,
    date_code date NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_cartid OWNER TO postgres;

--
-- Name: counter_cartitemid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_cartitemid (
    user_id character varying(20) NOT NULL,
    date_code date NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_cartitemid OWNER TO postgres;

--
-- Name: counter_foodid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_foodid (
    seller_id character varying(20) NOT NULL,
    counter_value bigint DEFAULT '0'::bigint
);


ALTER TABLE public.counter_foodid OWNER TO postgres;

--
-- Name: counter_foodrecommendationitem; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_foodrecommendationitem (
    user_id character varying(20) NOT NULL,
    timestamp_date date DEFAULT CURRENT_TIMESTAMP NOT NULL,
    counter bigint DEFAULT '0'::bigint
);


ALTER TABLE public.counter_foodrecommendationitem OWNER TO postgres;

--
-- Name: counter_glucoseid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_glucoseid (
    user_id character varying(10) NOT NULL,
    counter_date date NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_glucoseid OWNER TO postgres;

--
-- Name: counter_healthdataid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_healthdataid (
    user_id character varying(20) NOT NULL,
    date_stamp date NOT NULL,
    counter bigint DEFAULT '0'::bigint
);


ALTER TABLE public.counter_healthdataid OWNER TO postgres;

--
-- Name: counter_id; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_id (
    registration_date date NOT NULL,
    counter bigint NOT NULL
);


ALTER TABLE public.counter_id OWNER TO postgres;

--
-- Name: counter_orderid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_orderid (
    user_id character varying(20) NOT NULL,
    date_code date NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_orderid OWNER TO postgres;

--
-- Name: counter_transactionid; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.counter_transactionid (
    payment_date date NOT NULL,
    user_id character varying(20) NOT NULL,
    counter bigint DEFAULT '1'::bigint
);


ALTER TABLE public.counter_transactionid OWNER TO postgres;

--
-- Name: delivery_log; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.delivery_log (
    log_id bigint NOT NULL,
    delivery_id bigint NOT NULL,
    log_status character varying(50) DEFAULT NULL::character varying,
    log_message text,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.delivery_log OWNER TO postgres;

--
-- Name: delivery_log_log_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.delivery_log_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.delivery_log_log_id_seq OWNER TO postgres;

--
-- Name: delivery_log_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.delivery_log_log_id_seq OWNED BY public.delivery_log.log_id;


--
-- Name: delivery_orders; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.delivery_orders (
    delivery_id bigint NOT NULL,
    order_id character varying(30) NOT NULL,
    courier_orderid character varying(100) NOT NULL,
    delivery_status character varying(50) DEFAULT NULL::character varying,
    delivery_fee bigint,
    pickup_address text,
    dropoff_address text,
    scheduled_time timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone
);


ALTER TABLE public.delivery_orders OWNER TO postgres;

--
-- Name: delivery_orders_delivery_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.delivery_orders_delivery_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.delivery_orders_delivery_id_seq OWNER TO postgres;

--
-- Name: delivery_orders_delivery_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.delivery_orders_delivery_id_seq OWNED BY public.delivery_orders.delivery_id;


--
-- Name: delivery_recipients; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.delivery_recipients (
    recipient_id bigint NOT NULL,
    delivery_id bigint NOT NULL,
    recipient_name character varying(100) DEFAULT NULL::character varying,
    recipient_phone character varying(20) DEFAULT NULL::character varying,
    recipient_address text,
    recipient_latitude numeric(10,7) DEFAULT NULL::numeric,
    recipient_longitude numeric(10,7) DEFAULT NULL::numeric,
    recipient_notes text
);


ALTER TABLE public.delivery_recipients OWNER TO postgres;

--
-- Name: delivery_recipients_recipient_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.delivery_recipients_recipient_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.delivery_recipients_recipient_id_seq OWNER TO postgres;

--
-- Name: delivery_recipients_recipient_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.delivery_recipients_recipient_id_seq OWNED BY public.delivery_recipients.recipient_id;


--
-- Name: doctor; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor (
    doctor_id character varying(20) NOT NULL,
    doctor_username character varying(30) NOT NULL,
    doctor_password character varying(255) NOT NULL,
    doctor_firstname character varying(50) NOT NULL,
    doctor_lastname character varying(50) DEFAULT NULL::character varying,
    doctor_email character varying(100) NOT NULL,
    doctor_phonenumber character varying(15) NOT NULL,
    doctor_specialist character varying(50) DEFAULT NULL::character varying,
    doctor_sip character varying(30) DEFAULT NULL::character varying,
    doctor_province character varying(50) DEFAULT NULL::character varying,
    doctor_city character varying(50) DEFAULT NULL::character varying,
    doctor_district character varying(50) DEFAULT NULL::character varying,
    doctor_gmapslink character varying(500) DEFAULT NULL::character varying,
    doctor_practiceaddress character varying(255) DEFAULT NULL::character varying,
    doctor_practiceschedule text,
    doctor_accountstatus boolean DEFAULT true NOT NULL,
    doctor_photopath character varying(255) DEFAULT NULL::character varying
);


ALTER TABLE public.doctor OWNER TO postgres;

--
-- Name: doctor_appointments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_appointments (
    appointment_id bigint NOT NULL,
    user_id character varying(20) NOT NULL,
    doctor_id character varying(20) NOT NULL,
    appointment_datetime timestamp with time zone NOT NULL,
    appointment_status public.doctor_appointments_appointment_status DEFAULT 'scheduled'::public.doctor_appointments_appointment_status NOT NULL,
    appointment_type public.doctor_appointments_appointment_type NOT NULL,
    appointment_reason text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone
);


ALTER TABLE public.doctor_appointments OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_appointments_appointment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_appointments_appointment_id_seq OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_appointments_appointment_id_seq OWNED BY public.doctor_appointments.appointment_id;


--
-- Name: doctor_availability; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_availability (
    availability_id bigint NOT NULL,
    doctor_id character varying(20) NOT NULL,
    day_of_week character varying(50) NOT NULL,
    start_time time without time zone NOT NULL,
    end_time time without time zone NOT NULL
);


ALTER TABLE public.doctor_availability OWNER TO postgres;

--
-- Name: doctor_availability_availability_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_availability_availability_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_availability_availability_id_seq OWNER TO postgres;

--
-- Name: doctor_availability_availability_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_availability_availability_id_seq OWNED BY public.doctor_availability.availability_id;


--
-- Name: doctor_consultation_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_consultation_records (
    record_id bigint NOT NULL,
    appointment_id bigint NOT NULL,
    doctor_notes text,
    doctor_diagnosis text,
    next_consultation boolean DEFAULT false,
    next_consultation_date date,
    recorded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone
);


ALTER TABLE public.doctor_consultation_records OWNER TO postgres;

--
-- Name: doctor_consultation_records_record_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_consultation_records_record_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_consultation_records_record_id_seq OWNER TO postgres;

--
-- Name: doctor_consultation_records_record_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_consultation_records_record_id_seq OWNED BY public.doctor_consultation_records.record_id;


--
-- Name: doctor_reviews; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_reviews (
    review_id bigint NOT NULL,
    doctor_id character varying(20) NOT NULL,
    user_id character varying(20) NOT NULL,
    review_rating smallint NOT NULL,
    review_comment text,
    review_date timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.doctor_reviews OWNER TO postgres;

--
-- Name: doctor_reviews_review_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_reviews_review_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_reviews_review_id_seq OWNER TO postgres;

--
-- Name: doctor_reviews_review_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_reviews_review_id_seq OWNED BY public.doctor_reviews.review_id;


--
-- Name: food; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food (
    food_id character varying(40) NOT NULL,
    seller_id character varying(20) DEFAULT NULL::character varying,
    food_categoryid character varying(10) NOT NULL,
    food_name character varying(100) NOT NULL,
    food_price bigint NOT NULL,
    food_calories integer,
    food_carbohydrate double precision,
    food_proteins double precision,
    food_fat double precision,
    food_sugar double precision,
    food_ingredients character varying(255) DEFAULT NULL::character varying,
    food_description text
);


ALTER TABLE public.food OWNER TO postgres;

--
-- Name: food_category; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_category (
    food_categoryid character varying(10) NOT NULL,
    food_category character varying(30) NOT NULL
);


ALTER TABLE public.food_category OWNER TO postgres;

--
-- Name: food_picture; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_picture (
    photo_id bigint NOT NULL,
    food_id character varying(20) DEFAULT NULL::character varying,
    food_photopath character varying(255) DEFAULT NULL::character varying,
    food_photodescription character varying(100) DEFAULT NULL::character varying
);


ALTER TABLE public.food_picture OWNER TO postgres;

--
-- Name: food_picture_photo_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.food_picture_photo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.food_picture_photo_id_seq OWNER TO postgres;

--
-- Name: food_picture_photo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.food_picture_photo_id_seq OWNED BY public.food_picture.photo_id;


--
-- Name: food_recommendation; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_recommendation (
    recommendation_id character varying(40) NOT NULL,
    user_id character varying(20) NOT NULL,
    generated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    notes text,
    source_agent character varying(50) DEFAULT NULL::character varying
);


ALTER TABLE public.food_recommendation OWNER TO postgres;

--
-- Name: food_recommendation_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_recommendation_items (
    item_id character varying(30) NOT NULL,
    recommendation_id character varying(40) NOT NULL,
    food_id character varying(30) NOT NULL,
    timestamp_date date DEFAULT CURRENT_TIMESTAMP NOT NULL
);


ALTER TABLE public.food_recommendation_items OWNER TO postgres;

--
-- Name: glucose_manual; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.glucose_manual (
    glucose_id character varying(30) NOT NULL,
    user_id character varying(20) NOT NULL,
    glucose_inputdate timestamp with time zone,
    glucose_value double precision NOT NULL,
    glucose_level bigint NOT NULL
);


ALTER TABLE public.glucose_manual OWNER TO postgres;

--
-- Name: message_attachments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.message_attachments (
    attachment_id bigint NOT NULL,
    message_id character varying(70) NOT NULL,
    file_url character varying(512) NOT NULL,
    file_type character varying(100) NOT NULL,
    file_name character varying(255) DEFAULT NULL::character varying,
    file_size_bytes bigint,
    uploaded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.message_attachments OWNER TO postgres;

--
-- Name: message_attachments_attachment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.message_attachments_attachment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.message_attachments_attachment_id_seq OWNER TO postgres;

--
-- Name: message_attachments_attachment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.message_attachments_attachment_id_seq OWNED BY public.message_attachments.attachment_id;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.notifications (
    notification_id bigint NOT NULL,
    user_id character varying(20) DEFAULT NULL::character varying,
    seller_id character varying(20) DEFAULT NULL::character varying,
    doctor_id character varying(20) DEFAULT NULL::character varying,
    message text NOT NULL,
    type character varying(50) NOT NULL,
    is_read boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    link character varying(255) DEFAULT NULL::character varying
);


ALTER TABLE public.notifications OWNER TO postgres;

--
-- Name: notifications_notification_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.notifications_notification_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.notifications_notification_id_seq OWNER TO postgres;

--
-- Name: notifications_notification_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.notifications_notification_id_seq OWNED BY public.notifications.notification_id;


--
-- Name: seller; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seller (
    seller_id character varying(20) NOT NULL,
    seller_username character varying(50) NOT NULL,
    seller_password character varying(255) NOT NULL,
    seller_name character varying(50) NOT NULL,
    seller_businessname character varying(50) NOT NULL,
    seller_email character varying(50) NOT NULL,
    seller_phonenumber bigint NOT NULL,
    seller_province character varying(50) DEFAULT NULL::character varying,
    seller_city character varying(50) DEFAULT NULL::character varying,
    seller_district character varying(50) DEFAULT NULL::character varying,
    seller_gmapslink character varying(50) DEFAULT NULL::character varying,
    seller_lat character varying(50) DEFAULT NULL::character varying,
    seller_long character varying(50) DEFAULT NULL::character varying,
    seller_address text NOT NULL,
    seller_logopath text,
    seller_bannerpath character varying(255) DEFAULT NULL::character varying,
    seller_joindate date DEFAULT CURRENT_TIMESTAMP,
    seller_status public.seller_seller_status DEFAULT 'active'::public.seller_seller_status
);


ALTER TABLE public.seller OWNER TO postgres;

--
-- Name: seller_promotions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seller_promotions (
    promotion_id bigint NOT NULL,
    promotion_code character varying(50) NOT NULL,
    promotion_type public.seller_promotions_promotion_type NOT NULL,
    promotion_value bigint NOT NULL,
    minimum_order bigint DEFAULT '0'::bigint,
    start_date timestamp with time zone NOT NULL,
    end_date timestamp with time zone NOT NULL,
    usage_limit bigint,
    per_user_limit bigint,
    applies_to_sellerid character varying(20) DEFAULT NULL::character varying,
    applies_to_foodid character varying(40) DEFAULT NULL::character varying,
    applies_to_categoryid character varying(10) DEFAULT NULL::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone
);


ALTER TABLE public.seller_promotions OWNER TO postgres;

--
-- Name: seller_promotions_promotion_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.seller_promotions_promotion_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.seller_promotions_promotion_id_seq OWNER TO postgres;

--
-- Name: seller_promotions_promotion_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.seller_promotions_promotion_id_seq OWNED BY public.seller_promotions.promotion_id;


--
-- Name: seller_reviews; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seller_reviews (
    review_id bigint NOT NULL,
    seller_id character varying(20) NOT NULL,
    user_id character varying(20) NOT NULL,
    review_rating smallint NOT NULL,
    review_comment text,
    review_date date DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.seller_reviews OWNER TO postgres;

--
-- Name: seller_reviews_review_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.seller_reviews_review_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.seller_reviews_review_id_seq OWNER TO postgres;

--
-- Name: seller_reviews_review_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.seller_reviews_review_id_seq OWNED BY public.seller_reviews.review_id;


--
-- Name: user_addresses; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_addresses (
    address_id bigint NOT NULL,
    user_id character varying(20) NOT NULL,
    address_line1 character varying(255) NOT NULL,
    address_line2 character varying(255) DEFAULT NULL::character varying,
    address_city character varying(100) NOT NULL,
    address_province character varying(100) DEFAULT NULL::character varying,
    address_postalcode character varying(20) DEFAULT NULL::character varying,
    address_latitude numeric(10,7) DEFAULT NULL::numeric,
    address_longitude numeric(10,7) DEFAULT NULL::numeric,
    address_label character varying(50) DEFAULT NULL::character varying,
    is_default boolean DEFAULT false
);


ALTER TABLE public.user_addresses OWNER TO postgres;

--
-- Name: user_addresses_address_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_addresses_address_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_addresses_address_id_seq OWNER TO postgres;

--
-- Name: user_addresses_address_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_addresses_address_id_seq OWNED BY public.user_addresses.address_id;


--
-- Name: user_cart; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_cart (
    cart_id character varying(30) NOT NULL,
    user_id character varying(20) DEFAULT NULL::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    total_price bigint DEFAULT '0'::bigint,
    cart_status public.user_cart_cart_status DEFAULT 'active'::public.user_cart_cart_status NOT NULL
);


ALTER TABLE public.user_cart OWNER TO postgres;

--
-- Name: user_cartitems; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_cartitems (
    cartitem_id character varying(30) NOT NULL,
    cart_id character varying(30) DEFAULT NULL::character varying,
    user_id character varying(20) DEFAULT NULL::character varying,
    food_id character varying(30) DEFAULT NULL::character varying,
    food_price bigint,
    quantity integer NOT NULL,
    subtotal bigint DEFAULT '0'::bigint
);


ALTER TABLE public.user_cartitems OWNER TO postgres;

--
-- Name: user_healthdata; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_healthdata (
    healthdata_id character varying(30) NOT NULL,
    user_id character varying(20) DEFAULT NULL::character varying,
    healthdata_recordtime timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    healthdata_weight numeric(5,2) DEFAULT NULL::numeric,
    healthdata_height numeric(5,2) DEFAULT NULL::numeric,
    healthdata_bmi numeric(5,2) DEFAULT NULL::numeric,
    healthdata_bloodpressure character varying(20) DEFAULT NULL::character varying,
    healthdata_heartrate bigint,
    healthdata_glucose numeric(5,2) DEFAULT NULL::numeric,
    healthdata_notes text,
    recorded_by character varying(50) NOT NULL
);


ALTER TABLE public.user_healthdata OWNER TO postgres;

--
-- Name: user_order; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_order (
    order_id character varying(30) NOT NULL,
    user_id character varying(20) NOT NULL,
    seller_id character varying(20) DEFAULT NULL::character varying,
    cart_id character varying(30) NOT NULL,
    order_date timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    total_amount bigint NOT NULL,
    payment_status public.user_order_payment_status DEFAULT 'Pending'::public.user_order_payment_status,
    shipping_address text,
    order_status public.user_order_order_status DEFAULT 'Processing'::public.user_order_order_status,
    order_notes text,
    order_rejectreason text NOT NULL
);


ALTER TABLE public.user_order OWNER TO postgres;

--
-- Name: user_sellerfavorites; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_sellerfavorites (
    favorite_id bigint NOT NULL,
    user_id character varying(20) NOT NULL,
    seller_id character varying(20) NOT NULL
);


ALTER TABLE public.user_sellerfavorites OWNER TO postgres;

--
-- Name: user_sellerfavorites_favorite_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_sellerfavorites_favorite_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_sellerfavorites_favorite_id_seq OWNER TO postgres;

--
-- Name: user_sellerfavorites_favorite_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_sellerfavorites_favorite_id_seq OWNED BY public.user_sellerfavorites.favorite_id;


--
-- Name: user_transaction; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_transaction (
    payment_id character varying(30) NOT NULL,
    order_id character varying(30) NOT NULL,
    user_id character varying(20) NOT NULL,
    payment_method character varying(30) DEFAULT NULL::character varying,
    payment_amount bigint NOT NULL,
    payment_status public.user_transaction_payment_status DEFAULT 'Pending'::public.user_transaction_payment_status,
    gateway_transaction_id character varying(100) DEFAULT NULL::character varying,
    gateway_response text,
    approval_code character varying(50) DEFAULT NULL::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    paid_at timestamp with time zone
);


ALTER TABLE public.user_transaction OWNER TO postgres;

--
-- Name: user_vip; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_vip (
    user_id character varying(20) NOT NULL,
    activated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    payment_id character varying(30) DEFAULT NULL::character varying,
    notes text,
    vip_status public.user_vip_vip_status DEFAULT 'Pending'::public.user_vip_vip_status
);


ALTER TABLE public.user_vip OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id character varying(36) NOT NULL,
    user_username character varying(50),
    user_password character varying(255),
    user_firstname character varying(50),
    user_lastname character varying(50) DEFAULT NULL::character varying,
    user_email character varying(100),
    user_dob date,
    user_gender public.users_user_gender,
    user_accounttype smallint DEFAULT '0'::smallint,
    user_name_auth character varying(255),
    user_avatar_url text,
    user_provider character varying(50),
    user_provider_user_id character varying(255),
    user_raw_data jsonb,
    user_created_at_auth timestamp with time zone,
    user_updated_at_auth timestamp with time zone,
    user_last_login_at timestamp with time zone,
    user_email_auth character varying(255)
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: TABLE users; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.users IS 'Unified user table supporting both traditional username/password and OAuth authentication';


--
-- Name: COLUMN users.user_username; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_username IS 'Username for traditional auth (NULL for OAuth-only users)';


--
-- Name: COLUMN users.user_password; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_password IS 'Hashed password for traditional auth (NULL for OAuth-only users)';


--
-- Name: COLUMN users.user_email; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_email IS 'Primary email (used for both auth types)';


--
-- Name: COLUMN users.user_provider; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_provider IS 'OAuth provider name (google, facebook, etc.) - NULL for traditional auth';


--
-- Name: COLUMN users.user_provider_user_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_provider_user_id IS 'User ID from OAuth provider - NULL for traditional auth';


--
-- Name: COLUMN users.user_email_auth; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_email_auth IS 'Email from OAuth provider (may differ from primary email)';


--
-- Name: users_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_auth (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255),
    avatar_url text,
    provider character varying(50) NOT NULL,
    provider_user_id character varying(255) NOT NULL,
    raw_data jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_login_at timestamp with time zone
);


ALTER TABLE public.users_auth OWNER TO postgres;

--
-- Name: users_refresh_tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id character varying(36) NOT NULL,
    token_hash character varying(255) NOT NULL,
    device_info character varying(255),
    ip_address inet,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    revoked_at timestamp with time zone,
    replaced_by_token_id uuid
);


ALTER TABLE public.users_refresh_tokens OWNER TO postgres;

--
-- Name: delivery_log log_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_log ALTER COLUMN log_id SET DEFAULT nextval('public.delivery_log_log_id_seq'::regclass);


--
-- Name: delivery_orders delivery_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_orders ALTER COLUMN delivery_id SET DEFAULT nextval('public.delivery_orders_delivery_id_seq'::regclass);


--
-- Name: delivery_recipients recipient_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_recipients ALTER COLUMN recipient_id SET DEFAULT nextval('public.delivery_recipients_recipient_id_seq'::regclass);


--
-- Name: doctor_appointments appointment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments ALTER COLUMN appointment_id SET DEFAULT nextval('public.doctor_appointments_appointment_id_seq'::regclass);


--
-- Name: doctor_availability availability_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability ALTER COLUMN availability_id SET DEFAULT nextval('public.doctor_availability_availability_id_seq'::regclass);


--
-- Name: doctor_consultation_records record_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records ALTER COLUMN record_id SET DEFAULT nextval('public.doctor_consultation_records_record_id_seq'::regclass);


--
-- Name: doctor_reviews review_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews ALTER COLUMN review_id SET DEFAULT nextval('public.doctor_reviews_review_id_seq'::regclass);


--
-- Name: food_picture photo_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_picture ALTER COLUMN photo_id SET DEFAULT nextval('public.food_picture_photo_id_seq'::regclass);


--
-- Name: message_attachments attachment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments ALTER COLUMN attachment_id SET DEFAULT nextval('public.message_attachments_attachment_id_seq'::regclass);


--
-- Name: notifications notification_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications ALTER COLUMN notification_id SET DEFAULT nextval('public.notifications_notification_id_seq'::regclass);


--
-- Name: seller_promotions promotion_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_promotions ALTER COLUMN promotion_id SET DEFAULT nextval('public.seller_promotions_promotion_id_seq'::regclass);


--
-- Name: seller_reviews review_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_reviews ALTER COLUMN review_id SET DEFAULT nextval('public.seller_reviews_review_id_seq'::regclass);


--
-- Name: user_addresses address_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_addresses ALTER COLUMN address_id SET DEFAULT nextval('public.user_addresses_address_id_seq'::regclass);


--
-- Name: user_sellerfavorites favorite_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sellerfavorites ALTER COLUMN favorite_id SET DEFAULT nextval('public.user_sellerfavorites_favorite_id_seq'::regclass);


--
-- Name: activity idx_17115_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity
    ADD CONSTRAINT idx_17115_primary PRIMARY KEY (activity_id);


--
-- Name: activity_categories idx_17125_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_categories
    ADD CONSTRAINT idx_17125_primary PRIMARY KEY (activity_categoryid);


--
-- Name: activity_recommendations idx_17132_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendations
    ADD CONSTRAINT idx_17132_primary PRIMARY KEY (recommendation_id);


--
-- Name: activity_recommendation_items idx_17138_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT idx_17138_primary PRIMARY KEY (item_id);


--
-- Name: chat_conversations idx_17145_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_conversations
    ADD CONSTRAINT idx_17145_primary PRIMARY KEY (conversation_id);


--
-- Name: chat_messages idx_17154_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT idx_17154_primary PRIMARY KEY (message_id);


--
-- Name: counter_activity_recommendationitem idx_17170_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_activity_recommendationitem
    ADD CONSTRAINT idx_17170_primary PRIMARY KEY (counter_date);


--
-- Name: counter_cartid idx_17175_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_cartid
    ADD CONSTRAINT idx_17175_primary PRIMARY KEY (user_id, date_code);


--
-- Name: counter_cartitemid idx_17181_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_cartitemid
    ADD CONSTRAINT idx_17181_primary PRIMARY KEY (user_id, date_code);


--
-- Name: counter_foodid idx_17187_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_foodid
    ADD CONSTRAINT idx_17187_primary PRIMARY KEY (seller_id);


--
-- Name: counter_foodrecommendationitem idx_17192_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_foodrecommendationitem
    ADD CONSTRAINT idx_17192_primary PRIMARY KEY (user_id, timestamp_date);


--
-- Name: counter_glucoseid idx_17199_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_glucoseid
    ADD CONSTRAINT idx_17199_primary PRIMARY KEY (user_id, counter_date);


--
-- Name: counter_healthdataid idx_17205_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_healthdataid
    ADD CONSTRAINT idx_17205_primary PRIMARY KEY (user_id, date_stamp);


--
-- Name: counter_id idx_17211_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_id
    ADD CONSTRAINT idx_17211_primary PRIMARY KEY (registration_date);


--
-- Name: counter_orderid idx_17216_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_orderid
    ADD CONSTRAINT idx_17216_primary PRIMARY KEY (user_id, date_code);


--
-- Name: counter_transactionid idx_17222_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.counter_transactionid
    ADD CONSTRAINT idx_17222_primary PRIMARY KEY (payment_date, user_id);


--
-- Name: delivery_log idx_17229_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_log
    ADD CONSTRAINT idx_17229_primary PRIMARY KEY (log_id);


--
-- Name: delivery_orders idx_17241_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_orders
    ADD CONSTRAINT idx_17241_primary PRIMARY KEY (delivery_id);


--
-- Name: delivery_recipients idx_17254_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_recipients
    ADD CONSTRAINT idx_17254_primary PRIMARY KEY (recipient_id);


--
-- Name: doctor idx_17266_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor
    ADD CONSTRAINT idx_17266_primary PRIMARY KEY (doctor_id);


--
-- Name: doctor_appointments idx_17289_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments
    ADD CONSTRAINT idx_17289_primary PRIMARY KEY (appointment_id);


--
-- Name: doctor_availability idx_17304_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability
    ADD CONSTRAINT idx_17304_primary PRIMARY KEY (availability_id);


--
-- Name: doctor_consultation_records idx_17314_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records
    ADD CONSTRAINT idx_17314_primary PRIMARY KEY (record_id);


--
-- Name: doctor_reviews idx_17325_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews
    ADD CONSTRAINT idx_17325_primary PRIMARY KEY (review_id);


--
-- Name: food idx_17336_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food
    ADD CONSTRAINT idx_17336_primary PRIMARY KEY (food_id);


--
-- Name: food_category idx_17347_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_category
    ADD CONSTRAINT idx_17347_primary PRIMARY KEY (food_categoryid);


--
-- Name: food_picture idx_17353_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_picture
    ADD CONSTRAINT idx_17353_primary PRIMARY KEY (photo_id);


--
-- Name: food_recommendation idx_17361_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_recommendation
    ADD CONSTRAINT idx_17361_primary PRIMARY KEY (recommendation_id);


--
-- Name: food_recommendation_items idx_17370_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_recommendation_items
    ADD CONSTRAINT idx_17370_primary PRIMARY KEY (item_id);


--
-- Name: glucose_manual idx_17378_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.glucose_manual
    ADD CONSTRAINT idx_17378_primary PRIMARY KEY (glucose_id, user_id);


--
-- Name: message_attachments idx_17386_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT idx_17386_primary PRIMARY KEY (attachment_id);


--
-- Name: notifications idx_17399_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT idx_17399_primary PRIMARY KEY (notification_id);


--
-- Name: seller idx_17414_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller
    ADD CONSTRAINT idx_17414_primary PRIMARY KEY (seller_id);


--
-- Name: seller_promotions idx_17437_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_promotions
    ADD CONSTRAINT idx_17437_primary PRIMARY KEY (promotion_id);


--
-- Name: seller_reviews idx_17453_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_reviews
    ADD CONSTRAINT idx_17453_primary PRIMARY KEY (review_id);


--
-- Name: user_addresses idx_17481_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_addresses
    ADD CONSTRAINT idx_17481_primary PRIMARY KEY (address_id);


--
-- Name: user_cart idx_17498_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cart
    ADD CONSTRAINT idx_17498_primary PRIMARY KEY (cart_id);


--
-- Name: user_cartitems idx_17507_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cartitems
    ADD CONSTRAINT idx_17507_primary PRIMARY KEY (cartitem_id);


--
-- Name: user_healthdata idx_17516_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_healthdata
    ADD CONSTRAINT idx_17516_primary PRIMARY KEY (healthdata_id);


--
-- Name: user_order idx_17530_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order
    ADD CONSTRAINT idx_17530_primary PRIMARY KEY (order_id);


--
-- Name: user_sellerfavorites idx_17545_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sellerfavorites
    ADD CONSTRAINT idx_17545_primary PRIMARY KEY (favorite_id);


--
-- Name: user_transaction idx_17552_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_transaction
    ADD CONSTRAINT idx_17552_primary PRIMARY KEY (payment_id);


--
-- Name: user_vip idx_17566_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_vip
    ADD CONSTRAINT idx_17566_primary PRIMARY KEY (user_id);


--
-- Name: users uq_user_oauth_provider; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uq_user_oauth_provider UNIQUE (user_provider, user_provider_user_id);


--
-- Name: users_auth users_auth_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_email_key UNIQUE (email);


--
-- Name: users_auth users_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_pkey PRIMARY KEY (id);


--
-- Name: users_auth users_auth_provider_provider_user_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_provider_provider_user_id_key UNIQUE (provider, provider_user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users_refresh_tokens users_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: users_refresh_tokens users_refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: users users_user_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_username_key UNIQUE (user_username);


--
-- Name: idx_17115_fk_activity_category; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17115_fk_activity_category ON public.activity USING btree (activity_categoryid);


--
-- Name: idx_17132_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17132_user_id ON public.activity_recommendations USING btree (user_id);


--
-- Name: idx_17138_activity_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17138_activity_id ON public.activity_recommendation_items USING btree (activity_id);


--
-- Name: idx_17138_recommendation_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17138_recommendation_id ON public.activity_recommendation_items USING btree (recommendation_id);


--
-- Name: idx_17154_conversation_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17154_conversation_id ON public.chat_messages USING btree (conversation_id);


--
-- Name: idx_17229_delivery_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17229_delivery_id ON public.delivery_log USING btree (delivery_id);


--
-- Name: idx_17241_order_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17241_order_id ON public.delivery_orders USING btree (order_id);


--
-- Name: idx_17254_delivery_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17254_delivery_id ON public.delivery_recipients USING btree (delivery_id);


--
-- Name: idx_17289_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17289_doctor_id ON public.doctor_appointments USING btree (doctor_id);


--
-- Name: idx_17289_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17289_user_id ON public.doctor_appointments USING btree (user_id);


--
-- Name: idx_17304_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17304_doctor_id ON public.doctor_availability USING btree (doctor_id);


--
-- Name: idx_17314_appointment_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17314_appointment_id ON public.doctor_consultation_records USING btree (appointment_id);


--
-- Name: idx_17325_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17325_doctor_id ON public.doctor_reviews USING btree (doctor_id);


--
-- Name: idx_17325_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17325_user_id ON public.doctor_reviews USING btree (user_id);


--
-- Name: idx_17336_kategoriid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17336_kategoriid ON public.food USING btree (food_categoryid);


--
-- Name: idx_17336_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17336_seller_id ON public.food USING btree (seller_id);


--
-- Name: idx_17353_food_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17353_food_id ON public.food_picture USING btree (food_id);


--
-- Name: idx_17361_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17361_user_id ON public.food_recommendation USING btree (user_id);


--
-- Name: idx_17370_food_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17370_food_id ON public.food_recommendation_items USING btree (food_id);


--
-- Name: idx_17370_recommendation_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17370_recommendation_id ON public.food_recommendation_items USING btree (recommendation_id);


--
-- Name: idx_17378_userid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17378_userid ON public.glucose_manual USING btree (user_id);


--
-- Name: idx_17386_message_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17386_message_id ON public.message_attachments USING btree (message_id);


--
-- Name: idx_17399_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17399_doctor_id ON public.notifications USING btree (doctor_id);


--
-- Name: idx_17399_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17399_seller_id ON public.notifications USING btree (seller_id);


--
-- Name: idx_17399_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17399_user_id ON public.notifications USING btree (user_id);


--
-- Name: idx_17414_idx_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17414_idx_email ON public.seller USING btree (seller_email);


--
-- Name: idx_17414_idx_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17414_idx_username ON public.seller USING btree (seller_username);


--
-- Name: idx_17414_penjualid; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17414_penjualid ON public.seller USING btree (seller_id);


--
-- Name: idx_17437_applies_to_category_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17437_applies_to_category_id ON public.seller_promotions USING btree (applies_to_categoryid);


--
-- Name: idx_17437_applies_to_food_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17437_applies_to_food_id ON public.seller_promotions USING btree (applies_to_foodid);


--
-- Name: idx_17437_applies_to_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17437_applies_to_seller_id ON public.seller_promotions USING btree (applies_to_sellerid);


--
-- Name: idx_17437_coupon_code; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17437_coupon_code ON public.seller_promotions USING btree (promotion_code);


--
-- Name: idx_17453_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17453_seller_id ON public.seller_reviews USING btree (seller_id);


--
-- Name: idx_17453_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17453_user_id ON public.seller_reviews USING btree (user_id);


--
-- Name: idx_17481_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17481_user_id ON public.user_addresses USING btree (user_id);


--
-- Name: idx_17498_fk_cart_user; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17498_fk_cart_user ON public.user_cart USING btree (user_id);


--
-- Name: idx_17507_fk_item_cart; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17507_fk_item_cart ON public.user_cartitems USING btree (cart_id);


--
-- Name: idx_17507_fk_item_food; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17507_fk_item_food ON public.user_cartitems USING btree (food_id);


--
-- Name: idx_17507_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17507_user_id ON public.user_cartitems USING btree (user_id);


--
-- Name: idx_17516_fk_user_health; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17516_fk_user_health ON public.user_healthdata USING btree (user_id);


--
-- Name: idx_17530_cart_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17530_cart_id ON public.user_order USING btree (cart_id);


--
-- Name: idx_17530_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17530_seller_id ON public.user_order USING btree (seller_id);


--
-- Name: idx_17530_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17530_user_id ON public.user_order USING btree (user_id);


--
-- Name: idx_17545_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17545_seller_id ON public.user_sellerfavorites USING btree (seller_id);


--
-- Name: idx_17545_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17545_user_id ON public.user_sellerfavorites USING btree (user_id);


--
-- Name: idx_17552_order_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17552_order_id ON public.user_transaction USING btree (order_id);


--
-- Name: idx_17552_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17552_user_id ON public.user_transaction USING btree (user_id);


--
-- Name: idx_17566_payment_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17566_payment_id ON public.user_vip USING btree (payment_id);


--
-- Name: idx_17566_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17566_user_id ON public.user_vip USING btree (user_id);


--
-- Name: idx_refresh_tokens_expires_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_expires_at ON public.users_refresh_tokens USING btree (expires_at);


--
-- Name: idx_refresh_tokens_token_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_token_hash ON public.users_refresh_tokens USING btree (token_hash);


--
-- Name: idx_refresh_tokens_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_user_id ON public.users_refresh_tokens USING btree (user_id);


--
-- Name: idx_user_addresses_default; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_addresses_default ON public.user_addresses USING btree (user_id, is_default);


--
-- Name: idx_user_addresses_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_addresses_user_id ON public.user_addresses USING btree (user_id);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_email ON public.users_auth USING btree (email);


--
-- Name: idx_users_email_auth; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_email_auth ON public.users USING btree (user_email_auth);


--
-- Name: idx_users_provider; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_provider ON public.users USING btree (user_provider, user_provider_user_id);


--
-- Name: idx_users_provider_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_provider_user_id ON public.users_auth USING btree (provider, provider_user_id);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_username ON public.users USING btree (user_username);


--
-- Name: chat_conversations on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.chat_conversations FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_chat_conversations();


--
-- Name: delivery_orders on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.delivery_orders FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_delivery_orders();


--
-- Name: doctor_appointments on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.doctor_appointments FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_doctor_appointments();


--
-- Name: doctor_consultation_records on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.doctor_consultation_records FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_doctor_consultation_records();


--
-- Name: glucose_manual on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.glucose_manual FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_glucose_manual();


--
-- Name: seller_promotions on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.seller_promotions FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_seller_promotions();


--
-- Name: user_addresses update_user_addresses_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_user_addresses_updated_at BEFORE UPDATE ON public.user_addresses FOR EACH ROW EXECUTE FUNCTION public.update_address_updated_at();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users_auth update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users_auth FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: activity_recommendation_items activity_recommendation_items_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT activity_recommendation_items_ibfk_1 FOREIGN KEY (recommendation_id) REFERENCES public.activity_recommendations(recommendation_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: activity_recommendation_items activity_recommendation_items_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT activity_recommendation_items_ibfk_2 FOREIGN KEY (activity_id) REFERENCES public.activity(activity_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: chat_messages chat_messages_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_ibfk_1 FOREIGN KEY (conversation_id) REFERENCES public.chat_conversations(conversation_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: delivery_log delivery_log_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_log
    ADD CONSTRAINT delivery_log_ibfk_1 FOREIGN KEY (delivery_id) REFERENCES public.delivery_orders(delivery_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: delivery_orders delivery_orders_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_orders
    ADD CONSTRAINT delivery_orders_ibfk_1 FOREIGN KEY (order_id) REFERENCES public.user_order(order_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: delivery_recipients delivery_recipients_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.delivery_recipients
    ADD CONSTRAINT delivery_recipients_ibfk_1 FOREIGN KEY (delivery_id) REFERENCES public.delivery_orders(delivery_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: doctor_appointments doctor_appointments_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments
    ADD CONSTRAINT doctor_appointments_ibfk_2 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_availability doctor_availability_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability
    ADD CONSTRAINT doctor_availability_ibfk_1 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_consultation_records doctor_consultation_records_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records
    ADD CONSTRAINT doctor_consultation_records_ibfk_1 FOREIGN KEY (appointment_id) REFERENCES public.doctor_appointments(appointment_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_reviews doctor_reviews_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews
    ADD CONSTRAINT doctor_reviews_ibfk_1 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: activity fk_activity_category; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity
    ADD CONSTRAINT fk_activity_category FOREIGN KEY (activity_categoryid) REFERENCES public.activity_categories(activity_categoryid) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_cartitems fk_item_cart; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cartitems
    ADD CONSTRAINT fk_item_cart FOREIGN KEY (cart_id) REFERENCES public.user_cart(cart_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: food food_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food
    ADD CONSTRAINT food_ibfk_1 FOREIGN KEY (food_categoryid) REFERENCES public.food_category(food_categoryid) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: food food_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food
    ADD CONSTRAINT food_ibfk_2 FOREIGN KEY (seller_id) REFERENCES public.seller(seller_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: food_recommendation_items food_recommendation_items_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_recommendation_items
    ADD CONSTRAINT food_recommendation_items_ibfk_1 FOREIGN KEY (recommendation_id) REFERENCES public.food_recommendation(recommendation_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: food_recommendation_items food_recommendation_items_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_recommendation_items
    ADD CONSTRAINT food_recommendation_items_ibfk_2 FOREIGN KEY (food_id) REFERENCES public.food(food_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: message_attachments message_attachments_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_ibfk_1 FOREIGN KEY (message_id) REFERENCES public.chat_messages(message_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: notifications notifications_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_ibfk_2 FOREIGN KEY (seller_id) REFERENCES public.seller(seller_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: notifications notifications_ibfk_3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_ibfk_3 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: seller_promotions seller_promotions_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_promotions
    ADD CONSTRAINT seller_promotions_ibfk_1 FOREIGN KEY (applies_to_sellerid) REFERENCES public.seller(seller_id) ON UPDATE RESTRICT ON DELETE SET NULL;


--
-- Name: seller_promotions seller_promotions_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_promotions
    ADD CONSTRAINT seller_promotions_ibfk_2 FOREIGN KEY (applies_to_foodid) REFERENCES public.food(food_id) ON UPDATE RESTRICT ON DELETE SET NULL;


--
-- Name: seller_promotions seller_promotions_ibfk_3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_promotions
    ADD CONSTRAINT seller_promotions_ibfk_3 FOREIGN KEY (applies_to_categoryid) REFERENCES public.food_category(food_categoryid) ON UPDATE RESTRICT ON DELETE SET NULL;


--
-- Name: seller_reviews seller_reviews_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_reviews
    ADD CONSTRAINT seller_reviews_ibfk_1 FOREIGN KEY (seller_id) REFERENCES public.seller(seller_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: user_cartitems user_cartitems_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cartitems
    ADD CONSTRAINT user_cartitems_ibfk_2 FOREIGN KEY (food_id) REFERENCES public.food(food_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: user_order user_order_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order
    ADD CONSTRAINT user_order_ibfk_2 FOREIGN KEY (cart_id) REFERENCES public.user_cart(cart_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: user_order user_order_ibfk_3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order
    ADD CONSTRAINT user_order_ibfk_3 FOREIGN KEY (seller_id) REFERENCES public.seller(seller_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: user_sellerfavorites user_sellerfavorites_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sellerfavorites
    ADD CONSTRAINT user_sellerfavorites_ibfk_2 FOREIGN KEY (seller_id) REFERENCES public.seller(seller_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: user_transaction user_transaction_ibfk_3; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_transaction
    ADD CONSTRAINT user_transaction_ibfk_3 FOREIGN KEY (order_id) REFERENCES public.user_order(order_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: user_vip user_vip_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_vip
    ADD CONSTRAINT user_vip_ibfk_2 FOREIGN KEY (payment_id) REFERENCES public.user_transaction(payment_id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: users_refresh_tokens users_refresh_tokens_replaced_by_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_replaced_by_token_id_fkey FOREIGN KEY (replaced_by_token_id) REFERENCES public.users_refresh_tokens(id);


--
-- Name: users_refresh_tokens users_refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--